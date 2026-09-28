-- | Finite-domain constraint solver (built-in backend) behind a small adapter
--   interface.  The core never depends on a particular solver: 'Solver' is a record of
--   functions and 'smtLib' exports any query for external SMT solvers (z3, cvc5).
module TZ.Solver
  ( Dom, Solver(..), builtinSolver, mkDom, solve, enumSat, spaceSize, primaries, orderSlots
  , smtLib, cands, assignSlot
  ) where

import Data.Bits ((.&.))
import Data.List (foldl', intercalate, nub, sort, sortOn)
import qualified Data.Map.Strict as M
import Data.Maybe (listToMaybe)
import TZ.Expr
import TZ.Types

data Dom = Dom
  { dVals :: M.Map String [Int]
  , dDerived :: M.Map String (String, Int -> Int)      -- derived slot -> (primary, value function)
  , dOps :: M.Map Int [Int]                             -- data id -> allowed action ids
  }

data Solver = Solver { solverName :: String, solverRun :: Dom -> CExpr -> Maybe Assign }

builtinSolver :: Solver
builtinSolver = Solver "builtin-finite-domain" (\d e -> solve d True e)

-- | Build the finite domain for a model. The extra expressions contribute the
--   integer thresholds that must be representable (value-1, value, value+1).
mkDom :: Ix -> [CExpr] -> Dom
mkDom ix exprs = Dom vals derived ops
  where
    m = ixModel ix
    nodes = map nId (moNodes m)
    consts s = nub (concat [[v - 1, v, v + 1] | e <- exprs, a <- atomsOf e, v <- constOf s a])
    constOf s a = case a of
      CGe x v | x == s -> [v]
      CGt x v | x == s -> [v]
      CLe x v | x == s -> [v]
      CLt x v | x == s -> [v]
      CEq x v | x == s -> [v]
      CIn x vs | x == s -> vs
      _ -> []
    maxRank = maximum (0 : map snd (allClasses m))
    rolesV = 0 : [2 ^ i | i <- [0 .. length (moRoles m) - 1]]
    winEdges = concat [[a - 1, a, b - 1, b] | (_, rs) <- M.elems (ixWin ix), (a, b) <- rs]
    mowV = sort (nub (filter (\t -> t >= 0 && t < 10080) ([0, 10079] ++ winEdges ++ consts "mow")))
    intDom s base = sort (nub (filter (>= 0) (base ++ consts s)))
    vals = M.fromList
      [ ("subj", nodes ++ [-1]), ("roles", rolesV), ("szone", map zId (moZones m) ++ [-1])
      , ("mfa", [0, 1]), ("dtrust", intDom "dtrust" [0 .. 5]), ("clearance", intDom "clearance" [0 .. maxRank])
      , ("res", nodes ++ [-1]), ("action", M.elems (ixAction ix) ++ [-1]), ("data", map dtId (moData m) ++ [-1])
      , ("zone", map zId (moZones m) ++ [-1]), ("env", M.elems (ixEnv ix) ++ [-1]), ("loc", M.elems (ixLoc ix) ++ [-1])
      , ("mow", mowV), ("approved", [0, 1]), ("emergency", [0, 1]), ("secure", [0, 1]), ("tenant", [0, 1]) ]
    dataById = M.fromList [(dtId d, d) | d <- moData m]
    zoneById = M.fromList [(zId z, z) | z <- moZones m]
    nodeById = M.fromList [(nId n, n) | n <- moNodes m]
    derived = M.fromList
      [ ("class", ("data", \d -> maybe 0 (\dr -> dataRank ix (dtName dr)) (M.lookup d dataById)))
      , ("ztrust", ("zone", \z -> maybe 0 zTrust (M.lookup z zoneById)))
      , ("zkind", ("zone", \z -> maybe (-1) (\zr -> maybe (-1) id (lookup (zKindS zr) (zip zoneKinds [0 ..]))) (M.lookup z zoneById)))
      , ("reskind", ("res", \r -> maybe (-1) (fromEnum . nKind) (M.lookup r nodeById)))
      , ("rzone", ("res", \r -> maybe (-1) (\nr -> maybe (-1) zId (M.lookup (nZone nr) (ixZone ix))) (M.lookup r nodeById))) ]
    ops = M.fromList
      [ (dtId d, [i | a <- names, Just i <- [M.lookup a (ixAction ix)]])
      | d <- moData m, Just v <- [getProp "operations" (dtProps d)], let names = valNames v, not (null names) ]

primaries :: Dom -> [String] -> [String]
primaries dom = nub . map (\s -> maybe s fst (M.lookup s (dDerived dom)))

slotOrder :: [String]
slotOrder = ["data", "res", "zone", "action", "env", "loc", "roles", "subj", "szone", "mfa", "dtrust", "clearance", "mow", "approved", "emergency", "secure", "tenant"]

orderSlots :: [String] -> [String]
orderSlots ss = sortOn (\s -> length (takeWhile (/= s) slotOrder)) ss

assignSlot :: Dom -> Assign -> String -> Int -> Assign
assignSlot dom a s v = foldl' (\m (k, (p, f)) -> if p == s then M.insert k (f v) m else m) (M.insert s v a) (M.toList (dDerived dom))

-- | Candidate values of a primary slot under the current partial assignment.
cands :: Dom -> Bool -> Assign -> String -> [Int]
cands dom useOps a s
  | s == "action", useOps, Just d <- M.lookup "data" a, Just allowed <- M.lookup d (dOps dom) = filter (`elem` allowed) base
  | s == "data", useOps, Just act <- M.lookup "action" a =
      filter (\d -> maybe True (act `elem`) (M.lookup d (dOps dom)) || d < 0) base
  | otherwise = base
  where base = M.findWithDefault [0] s (dVals dom)

-- | First satisfying assignment of the expression (with data-model axioms when 'useOps').
solve :: Dom -> Bool -> CExpr -> Maybe Assign
solve dom useOps e = case simp M.empty e of
  CF -> Nothing
  CT -> Just M.empty
  e' -> go M.empty e' (orderSlots (primaries dom (slotsOf e')))
  where
    go a ex [] = if evalD a ex then Just a else Nothing
    go a ex (s : ss) = listToMaybe
      [ r | v <- cands dom useOps a s
          , let a' = assignSlot dom a s v
          , let ex' = simp a' ex
          , ex' /= CF
          , Just r <- [if ex' == CT then Just a' else go a' ex' ss] ]

-- | Lazily enumerate every satisfying assignment over the given primary slots.
enumSat :: Dom -> Bool -> [String] -> CExpr -> [Assign]
enumSat dom useOps slots e = go M.empty e (orderSlots slots)
  where
    go a ex [] = [a | evalD a ex]
    go a ex (s : ss) = concat
      [ go a' ex' ss | v <- cands dom useOps a s
      , let a' = assignSlot dom a s v
      , let ex' = simp a' ex
      , ex' /= CF ]

spaceSize :: Dom -> [String] -> Integer
spaceSize dom slots = product [fromIntegral (length (M.findWithDefault [0] s (dVals dom))) | s <- primaries dom slots]

-- ---------------------------------------------------------------------------
-- SMT-LIB 2 export (adapter for external solvers)

smtLib :: Dom -> CExpr -> String
smtLib dom e = unlines $
  [ "(set-logic QF_LIA)" ]
  ++ ["(declare-const " ++ s ++ " Int)" | s <- allSlots]
  ++ [ "(assert (or " ++ unwords ["(= " ++ s ++ " " ++ lit v ++ ")" | v <- vs] ++ "))" | s <- prim, let vs = M.findWithDefault [0] s (dVals dom) ]
  ++ [ "(assert (=> (= " ++ p ++ " " ++ lit pv ++ ") (= " ++ k ++ " " ++ lit (f pv) ++ ")))"
     | (k, (p, f)) <- M.toList (dDerived dom), k `elem` allSlots, pv <- M.findWithDefault [0] p (dVals dom) ]
  ++ [ "(assert " ++ term e ++ ")", "(check-sat)", "(get-model)" ]
  where
    slots0 = slotsOf e
    prim = nub (primaries dom slots0)
    allSlots = nub (slots0 ++ prim)
    lit v = if v < 0 then "(- " ++ show (negate v) ++ ")" else show v
    term x = case x of
      CT -> "true"
      CF -> "false"
      CNot y -> "(not " ++ term y ++ ")"
      CAnd _ _ -> "(and " ++ unwords (map term (flatAnd x)) ++ ")"
      COr _ _ -> "(or " ++ unwords (map term (flatOr x)) ++ ")"
      CEq s v -> "(= " ++ s ++ " " ++ lit v ++ ")"
      CHas s m -> orOf [ "(= " ++ s ++ " " ++ lit v ++ ")" | v <- M.findWithDefault [0] s (dVals dom), v .&. m /= 0 ]
      CGe s v -> "(>= " ++ s ++ " " ++ lit v ++ ")"
      CGt s v -> "(> " ++ s ++ " " ++ lit v ++ ")"
      CLe s v -> "(<= " ++ s ++ " " ++ lit v ++ ")"
      CLt s v -> "(< " ++ s ++ " " ++ lit v ++ ")"
      CIn s vs -> orOf ["(= " ++ s ++ " " ++ lit v ++ ")" | v <- vs]
      CFlag s -> "(= " ++ s ++ " 1)"
      CWin _ rs -> orOf ["(and (>= mow " ++ show a ++ ") (< mow " ++ show b ++ "))" | (a, b) <- rs]
      CSlot s o t -> "(" ++ smtOp o ++ " " ++ s ++ " " ++ t ++ ")"
    orOf xs = if null xs then "false" else "(or " ++ unwords xs ++ ")"
    smtOp o = case o of OpEq -> "="; OpNe -> "distinct"; OpGe -> ">="; OpLe -> "<="; OpGt -> ">"; OpLt -> "<"
