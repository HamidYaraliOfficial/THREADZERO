-- | Canonical Security AST as JSON (what the Python layer and the web UI consume).
module TZ.Ast (astJ, valueJ, exprAstJ) where

import TZ.Json
import TZ.Types

valueJ :: Value -> J
valueJ v = case v of
  VId s -> str s
  VStr s -> str s
  VNum n -> jint n
  VDur n u -> str (show n ++ [u])
  VTime m -> str (show (m `div` 60) ++ ":" ++ (if m `mod` 60 < 10 then "0" else "") ++ show (m `mod` 60))
  VBool b -> jbool b
  VList xs -> arr (map valueJ xs)

propsJ :: Props -> J
propsJ ps = obj [(prKey p, valueJ (prVal p)) | p <- ps]

posJ :: Pos -> [(String, J)]
posJ p = [("file", str (pFile p)), ("line", jint (pLine p)), ("col", jint (pCol p))]

exprAstJ :: Expr -> J
exprAstJ e = case e of
  XBool b -> obj [("node", str "Bool"), ("value", jbool b)]
  XNum n -> obj [("node", str "Number"), ("value", jint n)]
  XStr s -> obj [("node", str "String"), ("value", str s)]
  XId _ n -> obj [("node", str "Entity"), ("name", str n)]
  XAttr _ n -> obj [("node", str "Attribute"), ("path", str n)]
  XCmp _ o a b -> obj [("node", str "Compare"), ("op", str (cmpText o)), ("left", exprAstJ a), ("right", exprAstJ b)]
  XIn _ a xs -> obj [("node", str "In"), ("left", exprAstJ a), ("items", arr (map exprAstJ xs))]
  XAnd a b -> obj [("node", str "And"), ("left", exprAstJ a), ("right", exprAstJ b)]
  XOr a b -> obj [("node", str "Or"), ("left", exprAstJ a), ("right", exprAstJ b)]
  XNot a -> obj [("node", str "Not"), ("arg", exprAstJ a)]
  XCall _ f as -> obj [("node", str "Call"), ("name", str f), ("args", arr (map exprAstJ as))]

astType :: NodeKind -> String
astType k
  | k `elem` [KUser, KIdentity, KAgent, KDevice] = "Identity"
  | k `elem` [KDatabase, KQueue, KFileStore, KCloud, KSecret] = "Resource"
  | otherwise = "Service"

astJ :: Model -> J
astJ m = obj
  [ ("node", str "Program")
  , ("project", obj [("name", str (moName m)), ("version", str (moVersion m)), ("timezone", str (moTz m))])
  , ("imports", strs (moImports m))
  , ("classifications", arr [obj ([("node", str "Classification"), ("name", str (cName c)), ("rank", jint (cRank c)), ("extends", jmaybe str (cExt c))] ++ posJ (cPos c)) | c <- moClasses m])
  , ("boundaries", arr ([obj ([("node", str "Boundary"), ("name", str (zName z)), ("trust", jint (zTrust z)), ("kind", str (zKindS z)), ("maxClass", jmaybe str (zMax z)), ("props", propsJ (zProps z))] ++ posJ (zPos z)) | z <- moZones m]
                        ++ [obj ([("node", str "BoundaryRule"), ("from", str (bFrom b)), ("to", str (bTo b)), ("props", propsJ (bProps b))] ++ posJ (bPos b)) | b <- moBounds m]))
  , ("roles", strs (map fst (moRoles m)))
  , ("environments", arr [obj [("node", str "Environment"), ("name", str n)] | (n, _) <- moEnvs m])
  , ("actions", arr [obj ([("node", str "Action"), ("name", str n)] ++ posJ p) | (n, p) <- moActions m])
  , ("dataTypes", arr [obj ([("node", str "DataType"), ("name", str (dtName d)), ("class", str (dtClass d)), ("props", propsJ (dtProps d))] ++ posJ (dtPos d)) | d <- moData m])
  , ("entities", arr [obj ([("node", str (astType (nKind n))), ("kind", str (kindName (nKind n))), ("name", str (nName n)), ("zone", str (nZone n)), ("props", propsJ (nProps n))] ++ posJ (nPos n)) | n <- moNodes m])
  , ("assignments", arr [obj [("identity", str i), ("role", str r)] | (i, r, _) <- moAssigns m])
  , ("windows", arr [obj ([("node", str "Window"), ("name", str (pdName w)), ("props", propsJ (pdProps w))] ++ posJ (pdPos w)) | w <- moWindows m])
  , ("flows", arr [obj ([("node", str "Flow"), ("name", str (fName f)), ("from", str (fFrom f)), ("to", str (fTo f)), ("carries", strs (fData f)), ("op", str (fOp f)), ("props", propsJ (fProps f))] ++ posJ (fPos f)) | f <- moFlows m])
  , ("policies", arr [ obj ([("node", str "Policy"), ("name", str (plName p)), ("version", str (plVersion p)), ("priority", jint (plPrio p)), ("scope", str (scopeS (plScope p))), ("extends", jmaybe str (plExtends p))
                            , ("rules", arr [obj ([("node", str "Rule"), ("name", str (ruName r)), ("effect", str (effectName (ruEffect r))), ("when", jmaybe exprAstJ (ruWhen r)), ("reason", jmaybe str (ruReason r)), ("obligations", strs (map effectName (ruObl r)))] ++ posJ (ruPos r)) | r <- plRules p])] ++ posJ (plPos p))
                     | p <- moPolicies m ])
  , ("assertions", arr [obj ([("node", str "Assertion"), ("name", str (asName a)), ("form", str (take 24 (show (asBody a))))] ++ posJ (asPos a)) | a <- moAsserts m])
  , ("constraints", arr [obj ([("node", str "Constraint"), ("name", str (csName c))] ++ posJ (csPos c)) | c <- moConstraints m])
  , ("declassifications", arr [obj ([("name", str (pdName d)), ("props", propsJ (pdProps d))] ++ posJ (pdPos d)) | d <- moDeclass m])
  , ("delegations", arr [obj ([("name", str (pdName d)), ("props", propsJ (pdProps d))] ++ posJ (pdPos d)) | d <- moDelegs m])
  , ("separations", arr [obj ([("name", str (pdName d)), ("props", propsJ (pdProps d))] ++ posJ (pdPos d)) | d <- moSeps m])
  , ("workflows", arr [obj ([("name", str (pdName d)), ("props", propsJ (pdProps d))] ++ posJ (pdPos d)) | d <- moWorkflows m])
  , ("properties", arr [obj [("name", str n), ("enabled", jbool b)] | (n, b, _) <- moPropsOn m]) ]
  where
    scopeS s = case s of ScGlobal -> "global"; ScZone z -> "zone:" ++ z; ScData d -> "data:" ++ d; ScResource r -> "resource:" ++ r
