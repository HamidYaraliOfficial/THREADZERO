-- | Canonical pretty printer: Model -> THREADZERO DSL source.
--   parse . pretty is the identity on models (positions ignored) — tested by the Haskell suite.
module TZ.Pretty (prettyModel, prettyExpr, prettyValue, quoteStr) where

import Data.List (intercalate)
import TZ.Types

quoteStr :: String -> String
quoteStr s = "\"" ++ concatMap esc s ++ "\""
  where
    esc '"' = "\\\""
    esc '\\' = "\\\\"
    esc '\n' = "\\n"
    esc '\t' = "\\t"
    esc '\r' = "\\r"
    esc c = [c]

prettyValue :: Value -> String
prettyValue v = case v of
  VId s -> s
  VStr s -> quoteStr s
  VNum n -> show n
  VDur n u -> show n ++ [u]
  VTime m -> show (m `div` 60) ++ ":" ++ (if m `mod` 60 < 10 then "0" else "") ++ show (m `mod` 60)
  VBool b -> if b then "true" else "false"
  VList xs -> "[" ++ intercalate ", " (map prettyValue xs) ++ "]"

prettyExpr :: Expr -> String
prettyExpr e = case e of
  XBool b -> if b then "true" else "false"
  XNum n -> show n
  XStr s -> quoteStr s
  XId _ n -> n
  XAttr _ n -> n
  XCmp _ o a b -> "(" ++ prettyExpr a ++ " " ++ cmpText o ++ " " ++ prettyExpr b ++ ")"
  XIn _ a xs -> "(" ++ prettyExpr a ++ " in [" ++ intercalate ", " (map prettyExpr xs) ++ "])"
  XAnd a b -> "(" ++ prettyExpr a ++ " and " ++ prettyExpr b ++ ")"
  XOr a b -> "(" ++ prettyExpr a ++ " or " ++ prettyExpr b ++ ")"
  XNot a -> "not " ++ paren a
  XCall _ f as -> f ++ "(" ++ intercalate ", " (map prettyExpr as) ++ ")"
  where
    paren x = case x of
      XAnd {} -> prettyExpr x
      XOr {} -> prettyExpr x
      XCmp {} -> prettyExpr x
      XIn {} -> prettyExpr x
      _ -> "(" ++ prettyExpr x ++ ")"

props :: Props -> String
props [] = ";"
props ps = " {\n" ++ concat ["  " ++ prKey p ++ ": " ++ prettyValue (prVal p) ++ ";\n" | p <- ps] ++ "}"

prettyModel :: Model -> String
prettyModel m = unlines' $
  [ ["project " ++ quoteStr (moName m) ++ " version " ++ quoteStr (moVersion m) ++ " timezone " ++ quoteStr (moTz m) ++ ";"]
  , ["import " ++ quoteStr i ++ ";" | i <- moImports m]
  , ["classification " ++ cName c ++ " rank " ++ show (cRank c) ++ maybe "" (" extends " ++) (cExt c) ++ ";" | c <- moClasses m]
  , ["zone " ++ zName z ++ " trust " ++ show (zTrust z) ++ " kind " ++ zKindS z ++ maybe "" (" max_class " ++) (zMax z) ++ props (zProps z) | z <- moZones m]
  , ["role " ++ n ++ ";" | (n, _) <- moRoles m]
  , ["env " ++ n ++ ";" | (n, _) <- moEnvs m]
  , ["action " ++ n ++ ";" | (n, _) <- moActions m]
  , ["location " ++ n ++ ";" | (n, _) <- moLocs m]
  , ["data " ++ dtName d ++ " class " ++ dtClass d ++ props (dtProps d) | d <- moData m]
  , [kindName (nKind n) ++ " " ++ nName n ++ " in " ++ nZone n ++ props (nProps n) | n <- moNodes m]
  , ["assign " ++ i ++ " role " ++ r ++ ";" | (i, r, _) <- moAssigns m]
  , ["window " ++ pdName w ++ props (pdProps w) | w <- moWindows m]
  , ["flow " ++ fName f ++ " from " ++ fFrom f ++ " to " ++ fTo f ++ " carries " ++ intercalate ", " (fData f) ++ " op " ++ fOp f ++ props (fProps f) | f <- moFlows m]
  , ["boundary " ++ bFrom b ++ " -> " ++ bTo b ++ props (bProps b) | b <- moBounds m]
  , map policy (moPolicies m)
  , ["declassify " ++ pdName d ++ props (pdProps d) | d <- moDeclass m]
  , ["delegate " ++ pdName d ++ props (pdProps d) | d <- moDelegs m]
  , ["separation " ++ pdName d ++ props (pdProps d) | d <- moSeps m]
  , ["workflow " ++ pdName d ++ props (pdProps d) | d <- moWorkflows m]
  , ["assert " ++ asName a ++ ": " ++ assertion (asBody a) ++ ";" | a <- moAsserts m]
  , ["constraint " ++ csName c ++ ": " ++ constraint (csBody c) ++ ";" | c <- moConstraints m]
  , ["property " ++ n ++ " " ++ (if b then "on" else "off") ++ ";" | (n, b, _) <- moPropsOn m]
  ]
  where
    unlines' = concatMap (\g -> if null g then "" else unlines g ++ "\n")

policy :: PolicyDef -> String
policy p =
  "policy " ++ plName p ++ " version " ++ quoteStr (plVersion p) ++ " priority " ++ show (plPrio p)
    ++ " scope " ++ scope (plScope p) ++ maybe "" (" extends " ++) (plExtends p) ++ " {\n"
    ++ concatMap rule (plRules p) ++ "}"
  where
    scope s = case s of
      ScGlobal -> "global"
      ScZone z -> "zone " ++ z
      ScData d -> "data " ++ d
      ScResource r -> "resource " ++ r
    rule r =
      "  rule " ++ ruName r ++ ": " ++ effectName (ruEffect r)
        ++ maybe "" (\e -> " when " ++ prettyExpr e) (ruWhen r)
        ++ maybe "" (\s -> " reason " ++ quoteStr s) (ruReason r)
        ++ (if null (ruObl r) then "" else " obligations [" ++ intercalate ", " (map effectName (ruObl r)) ++ "]")
        ++ maybe "" (\k -> " priority " ++ show k) (ruPrio r) ++ ";\n"

assertion :: Assertion -> String
assertion a = case a of
  AsNeverEnter d z -> "never data " ++ d ++ " enters zone " ++ z
  AsMustNot x o y -> x ++ " must_not " ++ o ++ " " ++ y
  AsActionAudit o -> "action " ++ o ++ " must audit"
  AsNodeControl n c -> n ++ " must_have " ++ c
  AsSecureChannel (Just f) -> "flow " ++ f ++ " must secure_channel"
  AsSecureChannel Nothing -> "all flows must secure_channel"
  AsNeverOp (Left d) o -> "never data " ++ d ++ " op " ++ o
  AsNeverOp (Right c) o -> "never class " ++ c ++ " op " ++ o
  AsRequest e f -> "request " ++ prettyExpr e ++ " must " ++ effectName f

constraint :: Constraint -> String
constraint c = case c of
  CoMaxClass z k -> "max_class " ++ z ++ " " ++ k
  CoNoFlow a b d -> "no_flow " ++ a ++ " " ++ b ++ maybe "" (" carrying " ++) d
  CoRequireControl k a b -> "require_control " ++ k ++ " on " ++ a ++ " -> " ++ b
  CoMaxFanout d n -> "max_fanout " ++ d ++ " " ++ show n
  CoAcyclicPolicies -> "acyclic_policies"
