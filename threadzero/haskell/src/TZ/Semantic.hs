-- | Semantic analyzer: references, types, permissions, trust boundaries, secrets,
--   classification consistency, circular dependencies. Every diagnostic carries a
--   code, exact file/line/column, the affected node and a human-readable hint.
module TZ.Semantic (checkModel, classPropagation, effClassOf) where

import Data.Char (isAlphaNum, isDigit, isUpper, isLower)
import Data.List (isPrefixOf, nub, sort, group, (\\))
import qualified Data.Map.Strict as M
import Data.Maybe (fromMaybe, isJust, mapMaybe)
import TZ.Types

err, warn, note :: String -> Pos -> String -> Diag
err = mkDiag SevError
warn = mkDiag SevWarning
note = mkDiag SevNotice

didYouMean :: String -> [String] -> Diag -> Diag
didYouMean n cs d = maybe d (\s -> withHint ("did you mean '" ++ s ++ "'?") d) (suggest n cs)

ref :: String -> Pos -> String -> String -> [String] -> [Diag]
ref code p what n cs
  | n `elem` cs = []
  | otherwise = [didYouMean n cs (mkDiag SevError code p ("undefined " ++ what ++ " '" ++ n ++ "'"))]

refs :: Pos -> String -> [String] -> [String] -> [Diag]
refs p what ns cs = concatMap (\n -> ref "TZ2001" p what n cs) ns

dups :: String -> [(String, Pos)] -> [Diag]
dups what xs = [ err "TZ2002" p (what ++ " '" ++ n ++ "' is defined more than once")
               | (n, p) <- drop1 xs ]
  where drop1 = go []
        go _ [] = []
        go seen ((n, p) : r) | n `elem` seen = (n, p) : go seen r
                             | otherwise = go (n : seen) r

secretKeys :: [String]
secretKeys = ["value", "secret", "secret_value", "password", "passwd", "token", "api_key", "apikey", "private_key", "credential", "credentials"]

looksSecret :: String -> Bool
looksSecret s = any (`isPrefixOf` s) ["sk_live_", "sk_test_", "ghp_", "gho_", "AKIA", "-----BEGIN", "eyJ", "xoxb-", "xoxp-"]
  || (length s >= 32 && all (\c -> isAlphaNum c || c `elem` "+/=_-") s && any isDigit s && any isUpper s && any isLower s)

checkModel :: Ix -> [Diag]
checkModel ix = concat
  [ namespace, classesC, zonesC, dataC, nodesC, assignsC, windowsC, flowsC, boundsC, policiesC
  , assertsC, declC, delegC, sepC, workflowC, propsC, secretsC, unusedC ]
  where
    m = ixModel ix
    zoneNames = map zName (moZones m)
    nodeNames = map nName (moNodes m)
    dataNames = map dtName (moData m)
    roleNames = map fst (moRoles m)
    actNames = allActions m
    classNames = map fst (allClasses m)
    flowNames = map fName (moFlows m)
    winNames = map pdName (moWindows m)
    validCtl = controlNames

    namespace = concat
      [ dups "zone" [(zName z, zPos z) | z <- moZones m], dups "data type" [(dtName d, dtPos d) | d <- moData m]
      , dups "node" [(nName n, nPos n) | n <- moNodes m], dups "flow" [(fName f, fPos f) | f <- moFlows m]
      , dups "policy" [(plName p, plPos p) | p <- moPolicies m], dups "role" (moRoles m)
      , dups "environment" (moEnvs m), dups "action" (moActions m), dups "location" (moLocs m)
      , dups "window" [(pdName w, pdPos w) | w <- moWindows m]
      , dups "assertion" [(asName a, asPos a) | a <- moAsserts m]
      , dups "constraint" [(csName c, csPos c) | c <- moConstraints m]
      , dups "classification" [(cName c, cPos c) | c <- moClasses m]
      , [ err "TZ2013" p ("'" ++ n ++ "' is a reserved word and cannot be used as a name")
        | (n, p) <- [(zName z, zPos z) | z <- moZones m] ++ [(dtName d, dtPos d) | d <- moData m] ++ [(nName x, nPos x) | x <- moNodes m] ++ moRoles m, n `elem` reservedWords ]
      , [ note "TZ2014" (nPos n) ("node '" ++ nName n ++ "' shares its name with another kind of entity; expressions are resolved by type but the model is easier to read with unique names")
        | n <- moNodes m, nName n `elem` (zoneNames ++ dataNames) ]
      , [ err "TZ2015" p "more than 30 roles are not supported by the 32-bit role mask" | length roleNames > 30, (_, p) <- take 1 (drop 30 (moRoles m)) ] ]

    classesC = concat
      [ [ err "TZ2002" (cPos c) ("classification '" ++ cName c ++ "' redefines a builtin classification") | cName c `elem` map fst builtinClasses ]
        ++ maybe [] (\e -> ref "TZ2001" (cPos c) "classification" e classNames
                        ++ [ err "TZ2009" (cPos c) ("classification '" ++ cName c ++ "' (rank " ++ show (cRank c) ++ ") is less sensitive than its base '" ++ e ++ "'")
                           | Just r <- [M.lookup e (ixClass ix)], cRank c < r ]) (cExt c)
      | c <- moClasses m ]

    zonesC = concat
      [ [ err "TZ2003" (zPos z) ("zone '" ++ zName z ++ "' trust level must be between 0 and 5") | zTrust z < 0 || zTrust z > 5 ]
        ++ [ didYouMean (zKindS z) zoneKinds (err "TZ2001" (zPos z) ("unknown zone kind '" ++ zKindS z ++ "'")) | zKindS z `notElem` zoneKinds ]
        ++ maybe [] (\c -> ref "TZ2001" (zPos z) "classification" c classNames) (zMax z)
      | z <- moZones m ]

    dataC = concat
      [ ref "TZ2001" (dtPos d) "classification" (dtClass d) classNames
        ++ refs (fromMaybe (dtPos d) (getPropPos "zones" pr)) "zone" (propNames "zones" pr) zoneNames
        ++ refs (fromMaybe (dtPos d) (getPropPos "operations" pr)) "action" (propNames "operations" pr) actNames
        ++ refs (fromMaybe (dtPos d) (getPropPos "derived_from" pr)) "data type" (propNames "derived_from" pr) dataNames
        ++ enumProp d "export" ["allow", "approval", "deny"] ++ enumProp d "logging" ["allowed", "redacted", "forbidden"]
        ++ [ warn "TZ2016" (dtPos d) ("data type '" ++ dtName d ++ "' is " ++ dtClass d ++ " but has no encryption requirement") | dataRank ix (dtName d) >= 3, getProp "encryption" pr == Nothing ]
        ++ [ note "TZ2017" (dtPos d) ("data type '" ++ dtName d ++ "' has no retention period") | dataRank ix (dtName d) >= 2, getProp "retention" pr == Nothing ]
      | d <- moData m, let pr = dtProps d ]
    enumProp d k allowed = case getProp k (dtProps d) >>= valText of
      Just v | v `notElem` allowed -> [ err "TZ2003" (fromMaybe (dtPos d) (getPropPos k (dtProps d))) ("property '" ++ k ++ "' must be one of: " ++ unwords allowed) ]
      _ -> []

    nodesC = concat
      [ ref "TZ2001" (nPos n) "zone" (nZone n) zoneNames
        ++ refs pp "control" (filter (`notElem` validCtl) (propNames "controls" pr)) validCtl
        ++ refs pp "control" (filter (`notElem` validCtl) (propNames "egress_controls" pr)) validCtl
        ++ refs pp "data type" (propNames "stores" pr) dataNames
        ++ refs pp "role" (propNames "roles" pr) roleNames
        ++ maybe [] (\c -> ref "TZ2001" pp "classification" c classNames) (propText "clearance" pr)
        ++ [ note "TZ2018" (nPos n) ("secret '" ++ nName n ++ "' should live in a zone of kind SecretZone") | nKind n == KSecret, maybe False ((/= "SecretZone") . zKindS) (M.lookup (nZone n) (ixZone ix)) ]
        ++ [ warn "TZ2019" (nPos n) ("node '" ++ nName n ++ "' stores " ++ d ++ " (" ++ className ix (dataRank ix d) ++ ") beyond its clearance " ++ maybe "?" id (propText "clearance" pr))
           | d <- propNames "stores" pr, Just c <- [propText "clearance" pr], Just r <- [M.lookup c (ixClass ix)], dataRank ix d > r ]
      | n <- moNodes m, let pr = nProps n, let pp = fromMaybe (nPos n) (getPropPos "controls" pr) ]

    assignsC = concat
      [ ref "TZ2001" p "identity" i (map nName (filter ((`elem` [KUser, KIdentity, KAgent, KService, KDevice, KApplication, KApproval]) . nKind) (moNodes m)))
        ++ ref "TZ2001" p "role" r roleNames
      | (i, r, p) <- moAssigns m ]

    windowsC = concat
      [ [ err "TZ2003" (pdPos w) ("window '" ++ pdName w ++ "' needs 'from' and 'to' times (HH:MM)") | getProp "from" pr == Nothing || getProp "to" pr == Nothing ]
        ++ [ err "TZ2003" (pdPos w) ("window '" ++ pdName w ++ "' kind must be open, maintenance or emergency") | Just k <- [propText "kind" pr], k `notElem` ["open", "maintenance", "emergency"] ]
        ++ [ note "TZ2020" (pdPos w) ("window '" ++ pdName w ++ "' uses time zone " ++ tz ++ " but the runtime evaluates windows in the project time zone " ++ moTz m)
           | Just tz <- [propText "tz" pr], tz /= moTz m ]
        ++ [ err "TZ2003" (pdPos w) ("window '" ++ pdName w ++ "': unknown day '" ++ d ++ "'") | d <- propNames "days" pr, d `notElem` ["weekdays", "weekends", "daily"], not (isJust (dayIdx d)) ]
      | w <- moWindows m, let pr = pdProps w ]

    flowsC = concat
      [ ref "TZ2001" p "node" (fFrom f) nodeNames ++ ref "TZ2001" p "node" (fTo f) nodeNames
        ++ concatMap (\d -> ref "TZ2001" p "data type" d dataNames) (fData f)
        ++ ref "TZ2001" p "action" (fOp f) actNames
        ++ [ err "TZ2004" p ("invalid flow '" ++ fName f ++ "': source and destination are the same node") | fFrom f == fTo f ]
        ++ [ err "TZ2004" p ("invalid flow '" ++ fName f ++ "': Publish requires a queue destination") | fOp f == "Publish", Just t <- [M.lookup (fTo f) (ixNode ix)], nKind t /= KQueue ]
        ++ [ err "TZ2004" p ("invalid flow '" ++ fName f ++ "': Subscribe requires a queue source") | fOp f == "Subscribe", Just s <- [M.lookup (fFrom f) (ixNode ix)], nKind s /= KQueue ]
        ++ [ err "TZ2004" p ("invalid flow '" ++ fName f ++ "': operation " ++ fOp f ++ " is not permitted for data type " ++ d)
           | d <- fData f, Just dr <- [M.lookup d (ixData ix)], Just v <- [getProp "operations" (dtProps dr)], fOp f `notElem` valNames v ]
        ++ refs pp "control" (filter (`notElem` validCtl) (propNames "controls" pr)) validCtl
        ++ [ err "TZ2003" pp "channel must be one of: tls, mtls, plain, internal" | Just c <- [propText "channel" pr], c `notElem` ["tls", "mtls", "plain", "internal"] ]
        ++ concat [ hard f d | d <- fData f ]
      | f <- moFlows m, let p = fPos f, let pr = fProps f, let pp = fromMaybe p (getPropPos "controls" pr) ]
    hard f d = case (M.lookup d (ixData ix), M.lookup (fTo f) (ixNode ix)) of
      (Just dr, Just tn) ->
        [ err "TZ2006" (fPos f) ("trust boundary violation: flow '" ++ fName f ++ "' moves " ++ d ++ " into zone " ++ nZone tn ++ ", which the data type does not allow (allowed: " ++ unwords zs ++ ")")
        | zs <- [propNames "zones" (dtProps dr)], not (null zs), nZone tn `notElem` zs ] ++
        [ err "TZ2009" (fPos f) ("data classification mismatch: " ++ d ++ " is " ++ dtClass dr ++ " but zone " ++ nZone tn ++ " accepts at most " ++ mc)
        | Just z <- [M.lookup (nZone tn) (ixZone ix)], Just mc <- [zMax z], Just r <- [M.lookup mc (ixClass ix)], dataRank ix d > r ]
      _ -> []

    boundsC = concat
      [ ref "TZ2001" (bPos b) "zone" (bFrom b) zoneNames ++ ref "TZ2001" (bPos b) "zone" (bTo b) zoneNames
        ++ refs (bPos b) "control" (filter (`notElem` validCtl) (propNames "require" (bProps b) ++ propNames "exempt" (bProps b))) validCtl
      | b <- moBounds m ]

    policiesC = concat
      [ (case plScope p of
           ScZone z -> ref "TZ2001" (plPos p) "zone" z zoneNames
           ScData d -> ref "TZ2001" (plPos p) "data type" d dataNames
           ScResource r -> ref "TZ2001" (plPos p) "node" r nodeNames
           ScGlobal -> [])
        ++ maybe [] (\e -> ref "TZ2001" (plPos p) "policy" e (map plName (moPolicies m))) (plExtends p)
        ++ dups ("rule in policy " ++ plName p) [(ruName r, ruPos r) | r <- plRules p]
      | p <- moPolicies m ] ++ cycles

    cycles =
      [ withNode (plName p) (err "TZ2007" (plPos p) ("circular policy dependency: " ++ unwords (intersperse' " -> " (path ++ [plName p]))))
      | p <- moPolicies m, Just path <- [cyc [plName p] (plName p)] ]
      where
        cyc seen n = case M.lookup n (ixPolicy ix) >>= plExtends of
          Nothing -> Nothing
          Just e | e == head (reverse seen) -> Just (reverse seen)
                 | e `elem` seen -> Nothing
                 | otherwise -> cyc (e : seen) e
        intersperse' s xs = case xs of [] -> []; [x] -> [x]; (x : r) -> x : s : intersperse' s r

    assertsC = concat
      [ case asBody a of
          AsNeverEnter d z -> ref "TZ2001" p "data type" d dataNames ++ ref "TZ2001" p "zone" z zoneNames
          AsMustNot x o y -> ref "TZ2001" p "node" x nodeNames ++ ref "TZ2001" p "node" y nodeNames ++ ref "TZ2001" p "action" o actNames
          AsActionAudit o -> ref "TZ2001" p "action" o actNames
          AsNodeControl n c -> ref "TZ2001" p "node" n nodeNames ++ ref "TZ2001" p "control" c validCtl
          AsSecureChannel (Just f) -> ref "TZ2001" p "flow" f flowNames
          AsSecureChannel Nothing -> []
          AsNeverOp (Left d) o -> ref "TZ2001" p "data type" d dataNames ++ ref "TZ2001" p "action" o actNames
          AsNeverOp (Right c) o -> ref "TZ2001" p "classification" c classNames ++ ref "TZ2001" p "action" o actNames
          AsRequest _ _ -> []
      | a <- moAsserts m, let p = asPos a ] ++ concat
      [ case csBody c of
          CoMaxClass z k -> ref "TZ2001" p "zone" z zoneNames ++ ref "TZ2001" p "classification" k classNames
          CoNoFlow a b d -> ref "TZ2001" p "zone" a zoneNames ++ ref "TZ2001" p "zone" b zoneNames ++ maybe [] (\x -> ref "TZ2001" p "data type" x dataNames) d
          CoRequireControl k a b -> ref "TZ2001" p "control" k validCtl ++ ref "TZ2001" p "zone" a zoneNames ++ ref "TZ2001" p "zone" b zoneNames
          CoMaxFanout d _ -> ref "TZ2001" p "data type" d dataNames
          CoAcyclicPolicies -> []
      | c <- moConstraints m, let p = csPos c ]

    declC = concat
      [ refs p "data type" (propNames "data" pr ++ propNames "produces" pr) dataNames
        ++ refs p "node" (propNames "via" pr ++ propNames "approval" pr) nodeNames
        ++ refs p "policy" (propNames "policy" pr) (map plName (moPolicies m))
        ++ [ warn "TZ2012" p ("declassification '" ++ pdName d ++ "' lowers a Restricted-or-higher classification without a human approval node")
           | [a] <- [propNames "data" pr], [b] <- [propNames "produces" pr], dataRank ix a >= 3, dataRank ix b < dataRank ix a, null (propNames "approval" pr) ]
      | d <- moDeclass m, let pr = pdProps d, let p = pdPos d ]

    delegC = concat
      [ refs p "identity" (propNames "from" pr ++ propNames "to" pr) nodeNames ++ refs p "role" (propNames "role" pr) roleNames
        ++ [ err "TZ2005" p ("impossible permission: delegator " ++ f ++ " does not hold role " ++ r ++ " and therefore cannot delegate it")
           | [f] <- [propNames "from" pr], [r] <- [propNames "role" pr], r `elem` roleNames, not (holds f r) ]
        ++ [ warn "TZ2021" p ("delegation '" ++ pdName d ++ "' has no expiry") | getProp "expires" pr == Nothing ]
      | d <- moDelegs m, let pr = pdProps d, let p = pdPos d ]
    holds i r = (i, r) `elem` [(a, b) | (a, b, _) <- moAssigns m]
      || any (\d -> propNames "to" (pdProps d) == [i] && propNames "role" (pdProps d) == [r] && propBool "revoked" False (pdProps d) == False && holdsVia d r) (moDelegs m)
    holdsVia d r = case propNames "from" (pdProps d) of
      [f] -> (f, r) `elem` [(a, b) | (a, b, _) <- moAssigns m]
      _ -> False

    sepC = concat [ refs (pdPos d) "role" (propNames "roles" (pdProps d)) roleNames | d <- moSeps m ]

    workflowC = concat
      [ refs (pdPos w) "flow" (propNames "steps" (pdProps w)) flowNames ++ refs (pdPos w) "node" (propNames "approvals" (pdProps w)) nodeNames | w <- moWorkflows m ]

    propsC =
      [ didYouMean n propertyNames (err "TZ2001" p ("unknown security property '" ++ n ++ "'")) | (n, _, p) <- moPropsOn m, n `notElem` propertyNames ]

    secretsC = concat
      [ [ err "TZ2011" p ("secret values must never appear in the model: property '" ++ k ++ "' is not allowed; store only a reference (e.g. reference: \"vault://kv/path\")")
        | k `elem` secretKeys ]
        ++ [ err "TZ2011" p ("property '" ++ k ++ "' looks like a secret value; use a reference instead") | Just s <- [valStr v], looksSecret s ]
      | (owner, pr) <- allProps, Prop k p v <- pr, let _ = owner ]
    valStr v = case v of VStr s -> Just s; _ -> Nothing
    allProps = [(nName n, nProps n) | n <- moNodes m] ++ [(dtName d, dtProps d) | d <- moData m]
      ++ [(zName z, zProps z) | z <- moZones m] ++ [(fName f, fProps f) | f <- moFlows m]

    unusedC =
      [ note "TZ2022" (dtPos d) ("data type '" ++ dtName d ++ "' is never carried by any flow") | d <- moData m, all ((dtName d `notElem`) . fData) (moFlows m), dtName d `notElem` concatMap (propNames "stores" . nProps) (moNodes m) ] ++
      [ note "TZ2023" (zPos z) ("zone '" ++ zName z ++ "' contains no nodes") | z <- moZones m, all ((/= zName z) . nZone) (moNodes m) ]

propertyNames :: [String]
propertyNames = ["Confidentiality", "Integrity", "Authenticity", "LeastPrivilege", "SeparationOfDuties", "Traceability", "DataMinimization", "BoundaryEnforcement"]

-- | Effective classification of every data type after propagation through derived_from
--   (max over sources) unless a declassify declaration explicitly allows a lower rank.
effClassOf :: Ix -> M.Map String Int
effClassOf ix = M.fromList [(dtName d, go [dtName d] (dtName d)) | d <- moData m]
  where
    m = ixModel ix
    go seen n =
      let own = dataRank ix n
          srcs = maybe [] (propNames "derived_from" . dtProps) (M.lookup n (ixData ix))
          allowed = [ s | d <- moDeclass m, propNames "produces" (pdProps d) == [n], s <- propNames "data" (pdProps d) ]
          inherited = [go (s : seen) s | s <- srcs, s `notElem` seen, s `notElem` allowed]
      in maximum (own : inherited)

-- | Classification propagation diagnostics + report rows: (data, declared, effective, sources).
classPropagation :: Ix -> ([Diag], [(String, Int, Int, [String])])
classPropagation ix = (ds, rows)
  where
    m = ixModel ix
    eff = effClassOf ix
    rows = [ (dtName d, dataRank ix (dtName d), M.findWithDefault 0 (dtName d) eff, propNames "derived_from" (dtProps d)) | d <- moData m ]
    ds = [ withNode n (err "TZ2009" (maybe noPos dtPos (M.lookup n (ixData ix)))
             ("data classification mismatch: " ++ n ++ " is declared " ++ className ix dcl ++ " but derives from " ++ unwords srcs ++ " and must be at least " ++ className ix e
              ++ "; raise its classification or add a 'declassify' declaration with approval"))
         | (n, dcl, e, srcs) <- rows, e > dcl ]
