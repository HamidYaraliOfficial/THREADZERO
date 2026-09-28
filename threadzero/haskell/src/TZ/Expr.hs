-- | Resolved (typed) policy conditions. The DSL expression language is type-checked
--   here and lowered to 'CExpr', the single semantic representation used by the
--   solver, the decision engine and — via JSON — every Python code generator target.
module TZ.Expr
  ( CExpr(..), Assign, slotVal, evalD, simp, slotsOf, atomsOf, csize
  , resolveExpr, cexprJ, cexprText, flatAnd, flatOr, andC, orC, notC, defaultVal, slotName
  ) where

import Data.Bits ((.&.))
import qualified Data.Map.Strict as M
import Data.List (intercalate, nub)
import TZ.Json
import TZ.Types

data CExpr
  = CT | CF | CNot CExpr | CAnd CExpr CExpr | COr CExpr CExpr
  | CEq String Int | CHas String Int | CGe String Int | CGt String Int | CLe String Int | CLt String Int
  | CIn String [Int] | CFlag String | CWin Int [(Int, Int)] | CSlot String CmpOp String
  deriving (Eq, Ord, Show)

type Assign = M.Map String Int

defaultVal :: String -> Int
defaultVal s
  | s `elem` ["roles", "mfa", "dtrust", "clearance", "class", "ztrust", "mow", "approved", "emergency", "secure", "tenant"] = 0
  | otherwise = -1

slotVal :: Assign -> String -> Int
slotVal a s = M.findWithDefault (defaultVal s) s a

cmpI :: CmpOp -> Int -> Int -> Bool
cmpI o a b = case o of OpEq -> a == b; OpNe -> a /= b; OpGe -> a >= b; OpLe -> a <= b; OpGt -> a > b; OpLt -> a < b

-- | Full evaluation (missing slots take their ABI default).
evalD :: Assign -> CExpr -> Bool
evalD a e = case e of
  CT -> True
  CF -> False
  CNot x -> not (evalD a x)
  CAnd x y -> evalD a x && evalD a y
  COr x y -> evalD a x || evalD a y
  CEq s v -> slotVal a s == v
  CHas s m -> slotVal a s .&. m /= 0
  CGe s v -> slotVal a s >= v
  CGt s v -> slotVal a s > v
  CLe s v -> slotVal a s <= v
  CLt s v -> slotVal a s < v
  CIn s vs -> slotVal a s `elem` vs
  CFlag s -> slotVal a s == 1
  CWin _ rs -> let t = slotVal a "mow" in any (\(x, y) -> t >= x && t < y) rs
  CSlot s o t -> cmpI o (slotVal a s) (slotVal a t)

andC, orC :: CExpr -> CExpr -> CExpr
andC CF _ = CF
andC _ CF = CF
andC CT y = y
andC x CT = x
andC x y | x == y = x
andC x y = CAnd x y
orC CT _ = CT
orC _ CT = CT
orC CF y = y
orC x CF = x
orC x y | x == y = x
orC x y = COr x y

notC :: CExpr -> CExpr
notC CT = CF
notC CF = CT
notC (CNot x) = x
notC x = CNot x

-- | Partial evaluation under a (partial) assignment.
simp :: Assign -> CExpr -> CExpr
simp a e = case e of
  CNot x -> notC (simp a x)
  CAnd x y -> andC (simp a x) (simp a y)
  COr x y -> orC (simp a x) (simp a y)
  CT -> CT
  CF -> CF
  CWin _ _ -> if M.member "mow" a then lit (evalD a e) else e
  CSlot s _ t -> if M.member s a && M.member t a then lit (evalD a e) else e
  _ -> case slotsOf e of
    [s] | M.member s a -> lit (evalD a e)
    _ -> e
  where lit b = if b then CT else CF

slotsOf :: CExpr -> [String]
slotsOf = nub . go
  where
    go e = case e of
      CNot x -> go x
      CAnd x y -> go x ++ go y
      COr x y -> go x ++ go y
      CEq s _ -> [s]
      CHas s _ -> [s]
      CGe s _ -> [s]
      CGt s _ -> [s]
      CLe s _ -> [s]
      CLt s _ -> [s]
      CIn s _ -> [s]
      CFlag s -> [s]
      CWin _ _ -> ["mow"]
      CSlot s _ t -> [s, t]
      _ -> []

atomsOf :: CExpr -> [CExpr]
atomsOf e = case e of
  CNot x -> atomsOf x
  CAnd x y -> atomsOf x ++ atomsOf y
  COr x y -> atomsOf x ++ atomsOf y
  CT -> []
  CF -> []
  a -> [a]

csize :: CExpr -> Int
csize e = case e of
  CNot x -> 1 + csize x
  CAnd x y -> 1 + csize x + csize y
  COr x y -> 1 + csize x + csize y
  _ -> 1

flatAnd, flatOr :: CExpr -> [CExpr]
flatAnd (CAnd a b) = flatAnd a ++ flatAnd b
flatAnd x = [x]
flatOr (COr a b) = flatOr a ++ flatOr b
flatOr x = [x]

-- ---------------------------------------------------------------------------
-- Resolution / type checking

type R a = Either Diag a

err :: String -> Pos -> String -> R a
err c p m = Left (mkDiag SevError c p m)

typeNames :: Ix -> Ty -> [String]
typeNames ix t = case t of
  TyRole -> M.keys (ixRole ix)
  TyZone -> M.keys (ixZone ix)
  TyAction -> M.keys (ixAction ix)
  TyNode -> M.keys (ixNode ix)
  TyKind -> [kindName k | k <- [minBound .. maxBound]]
  TyData -> M.keys (ixData ix)
  TyClass -> M.keys (ixClass ix)
  TyEnv -> M.keys (ixEnv ix)
  TyLoc -> M.keys (ixLoc ix)
  TyZKind -> zoneKinds
  _ -> []

litVal :: Ix -> Pos -> Ty -> Expr -> R Int
litVal ix fp ty e = case (ty, e) of
  (TyBool, XBool b) -> Right (if b then 1 else 0)
  (TyInt, XNum n) -> Right n
  (TyClass, XNum n) -> Right n
  (TyClass, XId p n) -> ident p n (\k -> M.lookup k (ixClass ix))
  (TyRole, XId p n) -> ident p n (\k -> (\i -> 2 ^ i) <$> M.lookup k (ixRole ix))
  (TyZone, XId p n) -> ident p n (\k -> zId <$> M.lookup k (ixZone ix))
  (TyNode, XId p n) -> ident p n (\k -> nId <$> M.lookup k (ixNode ix))
  (TyData, XId p n) -> ident p n (\k -> dtId <$> M.lookup k (ixData ix))
  (TyAction, XId p n) -> ident p n (\k -> M.lookup k (ixAction ix))
  (TyEnv, XId p n) -> ident p n (\k -> M.lookup k (ixEnv ix))
  (TyLoc, XId p n) -> ident p n (\k -> M.lookup k (ixLoc ix))
  (TyKind, XId p n) -> ident p n (\k -> fromEnum <$> kindFromName k)
  (TyZKind, XId p n) -> ident p n (\k -> lookup k (zip zoneKinds [0 ..]))
  _ -> err "TZ2003" (posOf e) ("type mismatch: expected a " ++ tyName ty ++ " value but found " ++ describe e)
  where
    posOf x = case x of XId p _ -> p; XAttr p _ -> p; _ -> fp
    ident p n f = case f n of
      Just v -> Right v
      Nothing ->
        Left (withHint' (suggest n (typeNames ix ty))
              (mkDiag SevError "TZ2001" p ("undefined " ++ tyName ty ++ " '" ++ n ++ "' in policy expression")))
    withHint' (Just s) d = withHint ("did you mean '" ++ s ++ "'?") d
    withHint' Nothing d = d

describe :: Expr -> String
describe e = case e of
  XBool _ -> "a boolean"; XNum _ -> "a number"; XStr _ -> "a string"; XId _ n -> "identifier '" ++ n ++ "'"
  XAttr _ n -> "attribute '" ++ n ++ "'"; _ -> "a compound expression"

flipOp :: CmpOp -> CmpOp
flipOp o = case o of OpGe -> OpLe; OpLe -> OpGe; OpGt -> OpLt; OpLt -> OpGt; x -> x

resolveExpr :: Ix -> Pos -> Expr -> R CExpr
resolveExpr ix fp = go
  where
    go e = case e of
      XBool b -> Right (if b then CT else CF)
      XAnd a b -> andC' <$> go a <*> go b
      XOr a b -> orC' <$> go a <*> go b
      XNot a -> CNot <$> go a
      XAttr p a -> case lookup a attrTable of
        Just (TyBool, s) -> Right (CFlag s)
        Just (t, _) -> err "TZ2003" p ("attribute '" ++ a ++ "' has type " ++ tyName t ++ " and cannot be used as a condition; compare it with a value")
        Nothing -> err "TZ2001" p ("unknown attribute '" ++ a ++ "'")
      XId p n -> err "TZ2003" p ("'" ++ n ++ "' is an entity name, not a condition; compare it with an attribute (e.g. zone == " ++ n ++ ")")
      XNum _ -> err "TZ2003" fp "a bare number is not a condition"
      XStr _ -> err "TZ2003" fp "a bare string is not a condition"
      XCmp p o l r -> cmp p o l r
      XIn p l rs -> inList p l rs
      XCall p f args -> case (f, args) of
        ("in_window", [XId ip w]) -> case M.lookup w (ixWin ix) of
          Just (i, rs) -> Right (CWin i rs)
          Nothing -> Left (maybe id (\s -> withHint ("did you mean '" ++ s ++ "'?")) (suggest w (M.keys (ixWin ix)))
                             (mkDiag SevError "TZ2001" ip ("undefined window '" ++ w ++ "'")))
        ("in_window", _) -> err "TZ2003" p "in_window expects exactly one window name"
        _ -> err "TZ2001" p ("unknown function '" ++ f ++ "' (available: in_window)")
    andC' a b = CAnd a b
    orC' a b = COr a b

    attr p a = case lookup a attrTable of
      Just x -> Right x
      Nothing -> err "TZ2001" p ("unknown attribute '" ++ a ++ "'")

    cmp p o l r = case (l, r) of
      (XAttr pa a, XAttr pb b) -> do
        (ta, sa) <- attr pa a
        (tb, sb) <- attr pb b
        if ta /= tb then err "TZ2003" p ("type mismatch: cannot compare " ++ tyName ta ++ " with " ++ tyName tb)
        else if ta `elem` [TyRole, TyBool] then err "TZ2003" p ("attribute-to-attribute comparison is not supported for " ++ tyName ta)
        else if o `notElem` [OpEq, OpNe] && ta `notElem` [TyInt, TyClass] then err "TZ2003" p ("operator '" ++ cmpText o ++ "' cannot order " ++ tyName ta ++ " values")
        else Right (CSlot sa o sb)
      (XAttr pa a, lit) -> attrLit p pa a o lit
      (lit, XAttr pb b) -> attrLit p pb b (flipOp o) lit
      _ -> err "TZ2003" p "a comparison must involve at least one attribute (e.g. zone.trust >= 3)"

    attrLit p pa a o lit = do
      (ty, slot) <- attr pa a
      v <- litVal ix fp ty lit
      case ty of
        TyRole | o == OpEq -> Right (CHas slot v)
               | o == OpNe -> Right (CNot (CHas slot v))
               | otherwise -> err "TZ2003" p "roles support only == / != / in"
        TyBool | o == OpEq -> Right (if v == 1 then CFlag slot else CNot (CFlag slot))
               | o == OpNe -> Right (if v == 1 then CNot (CFlag slot) else CFlag slot)
               | otherwise -> err "TZ2003" p "booleans support only == / !="
        _ | ty `elem` [TyInt, TyClass] -> Right (ordered slot o v)
          | o == OpEq -> Right (CEq slot v)
          | o == OpNe -> Right (CNot (CEq slot v))
          | otherwise -> err "TZ2003" p ("operator '" ++ cmpText o ++ "' cannot order " ++ tyName ty ++ " values")

    ordered s o v = case o of
      OpEq -> CEq s v; OpNe -> CNot (CEq s v); OpGe -> CGe s v; OpGt -> CGt s v; OpLe -> CLe s v; OpLt -> CLt s v

    inList p l rs = case l of
      XAttr pa a -> do
        (ty, slot) <- attr pa a
        vs <- mapM (litVal ix fp ty) rs
        case ty of
          TyRole -> Right (CHas slot (sum (nub vs)))
          TyBool -> err "TZ2003" p "'in' is not supported for booleans"
          _ -> Right (CIn slot (nub vs))
      _ -> err "TZ2003" p "the left side of 'in' must be an attribute"

-- ---------------------------------------------------------------------------
-- Rendering

slotName :: Ix -> String -> Int -> String
slotName ix s v = case s of
  "roles" -> unionNames [n | (n, i) <- M.toList (ixRole ix), v .&. (2 ^ i) /= 0]
  "szone" -> z; "rzone" -> z; "zone" -> z
  "res" -> nd; "subj" -> nd
  "data" -> lookupName [(dtId d, dtName d) | d <- moData m]
  "action" -> lookupName [(i, n) | (n, i) <- M.toList (ixAction ix)]
  "env" -> lookupName [(i, n) | (n, i) <- M.toList (ixEnv ix)]
  "loc" -> lookupName [(i, n) | (n, i) <- M.toList (ixLoc ix)]
  "reskind" -> lookupName [(fromEnum k, kindName k) | k <- [minBound .. maxBound]]
  "zkind" -> lookupName (zip [0 ..] zoneKinds)
  "class" -> className ix v
  "clearance" -> className ix v
  _ -> show v
  where
    m = ixModel ix
    z = lookupName [(zId x, zName x) | x <- moZones m]
    nd = lookupName [(nId x, nName x) | x <- moNodes m]
    lookupName tbl = maybe (show v) id (lookup v tbl)
    unionNames ns = if null ns then show v else intercalate "|" ns

attrOfSlot :: String -> String
attrOfSlot s = case [a | (a, (_, sl)) <- attrTable, sl == s] of (a : _) -> a; [] -> s

cexprText :: Ix -> CExpr -> String
cexprText ix = go
  where
    go e = case e of
      CT -> "true"
      CF -> "false"
      CNot x -> "not (" ++ go x ++ ")"
      CAnd _ _ -> intercalate " and " (map wrap (flatAnd e))
      COr _ _ -> intercalate " or " (map wrap (flatOr e))
      CEq s v -> attrOfSlot s ++ " == " ++ slotName ix s v
      CHas s m -> attrOfSlot s ++ " == " ++ slotName ix s m
      CGe s v -> attrOfSlot s ++ " >= " ++ slotName ix s v
      CGt s v -> attrOfSlot s ++ " > " ++ slotName ix s v
      CLe s v -> attrOfSlot s ++ " <= " ++ slotName ix s v
      CLt s v -> attrOfSlot s ++ " < " ++ slotName ix s v
      CIn s vs -> attrOfSlot s ++ " in [" ++ intercalate ", " (map (slotName ix s) vs) ++ "]"
      CFlag s -> attrOfSlot s
      CWin i _ -> "in_window(" ++ head ([n | (n, (k, _)) <- M.toList (ixWin ix), k == i] ++ [show i]) ++ ")"
      CSlot s o t -> attrOfSlot s ++ " " ++ cmpText o ++ " " ++ attrOfSlot t
    wrap x = case x of CAnd {} -> "(" ++ go x ++ ")"; COr {} -> "(" ++ go x ++ ")"; _ -> go x

cexprJ :: CExpr -> J
cexprJ e = case e of
  CT -> obj [("op", str "true")]
  CF -> obj [("op", str "false")]
  CNot x -> obj [("op", str "not"), ("arg", cexprJ x)]
  CAnd _ _ -> obj [("op", str "and"), ("args", arr (map cexprJ (flatAnd e)))]
  COr _ _ -> obj [("op", str "or"), ("args", arr (map cexprJ (flatOr e)))]
  CEq s v -> a2 "eq" s v
  CHas s m -> obj [("op", str "has"), ("slot", str s), ("mask", jint m)]
  CGe s v -> a2 "ge" s v
  CGt s v -> a2 "gt" s v
  CLe s v -> a2 "le" s v
  CLt s v -> a2 "lt" s v
  CIn s vs -> obj [("op", str "in"), ("slot", str s), ("vals", ints vs)]
  CFlag s -> obj [("op", str "flag"), ("slot", str s)]
  CWin i rs -> obj [("op", str "win"), ("id", jint i), ("ranges", arr [ints [a, b] | (a, b) <- rs])]
  CSlot s o t -> obj [("op", str "cmp"), ("cmp", str (cmpText o)), ("slot", str s), ("slot2", str t)]
  where a2 op s v = obj [("op", str op), ("slot", str s), ("val", jint v)]
