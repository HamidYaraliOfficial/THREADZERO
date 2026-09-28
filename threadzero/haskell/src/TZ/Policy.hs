-- | Policy compiler front half: rule resolution, precedence, the decision engine,
--   conflict detection, optimisation analysis, coverage, boundary requirement derivation
--   and automatic test-case generation.  All results are plain data that Python turns
--   into WASM / Rego / JS / middleware artifacts.
module TZ.Policy
  ( RuleIR(..), Decision(..), Conflict(..), Opt(..), Cov(..), TC(..)
  , buildRules, decide, conflicts, optimizations, policyCoverage, policyDiags, genTests
  , requiredControls, providedControls, lowKinds, normC, tablesJ, rulesJ, conflictsJ
  , optimizationsJ, testsJ, coverageJ, windowsJ, symbolsJ, policyDom, effectiveRuleCount
  ) where

import Data.Bits ((.&.), (.|.))
import Data.List (foldl', intercalate, nub, sortOn, (\\))
import qualified Data.Map.Strict as M
import Data.Maybe (fromMaybe, isJust, listToMaybe, mapMaybe)
import TZ.Expr
import TZ.Json
import TZ.Solver
import TZ.Types

data RuleIR = RuleIR
  { riIdx :: Int, riPolicy :: String, riName :: String, riEffect :: Effect, riCond :: CExpr
  , riReason :: String, riObl :: [Effect], riPrio :: Int, riSpec :: Int, riPos :: Pos
  , riVersion :: String, riScope :: Scope, riOrder :: Int
  } deriving (Show)

riId :: RuleIR -> String
riId r = riPolicy r ++ "." ++ riName r

scopeSpec :: Scope -> Int
scopeSpec s = case s of ScGlobal -> 0; ScZone _ -> 1; ScData _ -> 2; ScResource _ -> 3

scopeExpr :: Ix -> Scope -> CExpr
scopeExpr ix s = case s of
  ScGlobal -> CT
  ScZone z -> maybe CF (CEq "zone" . zId) (M.lookup z (ixZone ix))
  ScData d -> maybe CF (CEq "data" . dtId) (M.lookup d (ixData ix))
  ScResource r -> maybe CF (CEq "res" . nId) (M.lookup r (ixNode ix))

-- | Effective rules of one policy: own rules plus inherited (re-scoped) parent rules.
effectiveRules :: Ix -> PolicyDef -> [(String, Rule)]
effectiveRules ix p = go [plName p] p
  where
    go seen q =
      let own = [(plName p, r) | r <- plRules q]
          inherited = case plExtends q >>= \n -> M.lookup n (ixPolicy ix) of
            Just par | plName par `notElem` seen ->
              [ (plName p, r { ruName = plName par ++ "." ++ ruName r })
              | (_, r) <- go (plName par : seen) par ]
            _ -> []
          ownNames = map (ruName . snd) own
      in own ++ [x | x@(_, r) <- inherited, drop 1 (dropWhile (/= '.') (ruName r)) `notElem` ownNames]

effectiveRuleCount :: Ix -> Int
effectiveRuleCount ix = sum [length (effectiveRules ix p) | p <- moPolicies (ixModel ix)]

buildRules :: Ix -> ([RuleIR], [Diag])
buildRules ix = (assign sorted, concat errs)
  where
    m = ixModel ix
    resolved =
      [ (order, res)
      | (order, (p, r)) <- zip [0 ..] [(p, r) | p <- moPolicies m, (_, r) <- effectiveRules ix p]
      , let res = case maybe (Right CT) (resolveExpr ix (ruPos r)) (ruWhen r) of
              Left d -> Left (withNode (plName p ++ "." ++ ruName r) d)
              Right c -> Right (mk order p r c) ]
    mk order p r c = RuleIR
      { riIdx = 0, riPolicy = plName p, riName = ruName r, riEffect = ruEffect r
      , riCond = andC (scopeExpr ix (plScope p)) c
      , riReason = fromMaybe (effectName (ruEffect r) ++ " by " ++ plName p ++ "." ++ ruName r) (ruReason r)
      , riObl = nub (ruObl r ++ [ruEffect r | not (isTerminal (ruEffect r))])
      , riPrio = fromMaybe (plPrio p) (ruPrio r), riSpec = scopeSpec (plScope p)
      , riPos = ruPos r, riVersion = plVersion p, riScope = plScope p, riOrder = order }
    errs = [[d] | (_, Left d) <- resolved]
    rules = [r | (_, Right r) <- resolved]
    sorted = sortOn (\r -> (negate (riPrio r), negate (riSpec r), if riEffect r == EfDeny then 0 else 1 :: Int, riOrder r)) rules
    assign rs = [r { riIdx = i } | (i, r) <- zip [0 ..] rs]

-- ---------------------------------------------------------------------------
-- Decision engine (mirrors the generated WASM exactly)

data Decision = Decision { dcCode :: Int, dcReason :: Int, dcObl :: Int, dcMatched :: [Int] } deriving (Eq, Show)

decide :: [RuleIR] -> Assign -> Decision
decide rules a = Decision code reason obl (map riIdx matched)
  where
    matched = [r | r <- rules, evalD a (riCond r)]
    obl = foldl' (.|.) 0 [effectBit e | r <- matched, e <- riObl r, not (isTerminal e)]
    winner = listToMaybe [r | r <- matched, isTerminal (riEffect r)]
    (base, wreason) = case winner of
      Just r -> (if riEffect r == EfAllow then 1 else 0 :: Int, riIdx r)
      Nothing -> (0, -1)
    has e = [riIdx r | r <- matched, e `elem` riObl r]
    firstOf e = case has e of (i : _) -> i; [] -> -1
    (code, reason)
      | base == 0 = (0, wreason)
      | not (null (has EfQuarantine)) = (4, firstOf EfQuarantine)
      | not (null (has EfRequireTrustedZone)) && slotVal a "ztrust" < 3 = (0, firstOf EfRequireTrustedZone)
      | not (null (has EfRequireMfa)) && slotVal a "mfa" == 0 = (2, firstOf EfRequireMfa)
      | not (null (has EfRequireApproval)) && slotVal a "approved" == 0 = (3, firstOf EfRequireApproval)
      | otherwise = (1, wreason)

-- ---------------------------------------------------------------------------
-- Domain helper

policyDom :: Ix -> [RuleIR] -> Dom
policyDom ix rs = mkDom ix (map riCond rs)

-- ---------------------------------------------------------------------------
-- Conflicts

data Conflict = Conflict
  { cfKind :: String, cfLevel :: Level, cfAllow :: RuleIR, cfDeny :: RuleIR, cfWitness :: Assign
  , cfWinner :: RuleIR, cfExplain :: String }

conflicts :: Ix -> Dom -> [RuleIR] -> [Conflict]
conflicts ix dom rs =
  [ Conflict kind lvl a d w winner (explain kind a d winner)
  | a <- rs, riEffect a == EfAllow, d <- rs, riEffect d == EfDeny
  , Just w <- [solve dom True (andC (riCond a) (riCond d))]
  , let winner = if riIdx a < riIdx d then a else d
  , let kind | riPrio a == riPrio d && riSpec a == riSpec d = "DenyAllowAmbiguity"
             | riScope a /= riScope d = "ScopeConflict"
             | touchesClass a && touchesClass d = "DataClassificationConflict"
             | otherwise = "OrderingConflict"
  , let lvl | kind == "DenyAllowAmbiguity" = LMedium
            | riEffect winner == EfAllow = LHigh
            | otherwise = LLow ]
  where
    touchesClass r = any (`elem` ["class", "data"]) (slotsOf (riCond r))
    explain kind a d w = kind ++ ": allow rule " ++ riId a ++ " (priority " ++ show (riPrio a) ++ ", specificity " ++ show (riSpec a)
      ++ ") and deny rule " ++ riId d ++ " (priority " ++ show (riPrio d) ++ ", specificity " ++ show (riSpec d)
      ++ ") can match the same request; " ++ riId w ++ " (" ++ effectName (riEffect w) ++ ") wins"
      ++ (if kind == "DenyAllowAmbiguity" then " only because deny-overrides breaks the tie" else " by precedence")

-- ---------------------------------------------------------------------------
-- Optimisation analysis

normC :: CExpr -> CExpr
normC e = case e of
  CAnd _ _ -> foldr1 andC' (nub (map normC (flatAnd e)))
  COr _ _ -> foldr1 orC' (nub (map normC (flatOr e)))
  CNot x -> notC (normC x)
  _ -> e
  where
    andC' a b = if a == notC b || b == notC a then CF else andC a b
    orC' a b = if a == notC b || b == notC a then CT else orC a b

data Opt = Opt { opKind :: String, opRules :: [String], opMsg :: String, opPos :: Pos, opProposal :: String }

optimizations :: Ix -> Dom -> [RuleIR] -> [Opt]
optimizations ix dom rs = dead ++ shadowed ++ redundant ++ duplicates
  where
    dead = [ Opt "DeadRule" [riId r] ("rule " ++ riId r ++ " can never match any valid request") (riPos r) "remove the rule or fix its condition"
           | r <- rs, riCond r /= CF, solve dom False (riCond r) == Nothing ] ++
           [ Opt "DeadRule" [riId r] ("rule " ++ riId r ++ " has an unsatisfiable condition") (riPos r) "remove the rule" | r <- rs, riCond r == CF ]
    terminals = [r | r <- rs, isTerminal (riEffect r)]
    shadowed =
      [ Opt "UnreachableRule" [riId r, riId h]
          ("rule " ++ riId r ++ " is shadowed by " ++ riId h ++ " (higher precedence, condition subsumes it); its " ++ effectName (riEffect r) ++ " effect can never win")
          (riPos r) ("remove " ++ riId r ++ " or lower the priority of " ++ riId h)
      | r <- terminals, isJust (solve dom True (riCond r))
      , h <- terminals, riIdx h < riIdx r
      , solve dom True (andC (riCond r) (notC (riCond h))) == Nothing ]
    redundant =
      [ Opt "RedundantCondition" [riId r] ("rule " ++ riId r ++ " has a redundant condition: " ++ cexprText ix (riCond r) ++ " simplifies to " ++ cexprText ix n)
          (riPos r) ("replace the condition with: " ++ cexprText ix n)
      | r <- rs, let n = normC (riCond r), n /= riCond r, csize n < csize (riCond r) ]
    duplicates =
      [ Opt "DuplicateRule" [riId a, riId b] ("rules " ++ riId a ++ " and " ++ riId b ++ " have the same effect and condition") (riPos b) ("merge " ++ riId b ++ " into " ++ riId a)
      | (i, a) <- zip [0 :: Int ..] rs, (j, b) <- zip [0 ..] rs, i < j
      , riEffect a == riEffect b, normC (riCond a) == normC (riCond b), riObl a == riObl b ]

-- ---------------------------------------------------------------------------
-- Boundary controls

lowKinds :: [String]
lowKinds = ["PublicInternet", "UntrustedZone", "ThirdPartyZone", "PartnerZone", "Browser", "MobileClient"]

requiredControls :: Ix -> ZoneR -> ZoneR -> Int -> String -> [String]
requiredControls ix za zb c op
  | zName za == zName zb = []
  | otherwise = nub (derived \\ exempt) `union'` declared
  where
    m = ixModel ix
    ta = zTrust za; tb = zTrust zb; ka = zKindS za; kb = zKindS zb
    low z = zKindS z `elem` lowKinds || zTrust z <= 1
    up = ta < tb || low za
    down = ta > tb
    writeLike = op `elem` ["Create", "Write", "Transform", "Enrich", "Publish", "Copy"]
    derived =
      ["authentication" | up] ++ ["authorization" | tb >= 2] ++ ["encryption" | c >= 1 || low za || low zb]
      ++ ["integrity_check" | c >= 2] ++ ["schema_validation" | up && low za && writeLike && tb >= 2]
      ++ ["input_validation" | up && low za && writeLike && tb >= 2] ++ ["rate_limit" | low za && tb >= 2]
      ++ ["output_filtering" | down && c >= 1] ++ ["redaction" | down && c >= 2 && low zb]
      ++ ["data_minimization" | kb `elem` ["ThirdPartyZone", "PartnerZone"] && c >= 2]
      ++ ["audit" | c >= 2 || op `elem` ["Export", "Delete", "Copy"]]
      ++ ["approval" | down && c >= 3 && op == "Export"]
      ++ ["token_exchange" | ka `elem` ["PartnerZone", "ThirdPartyZone"] && tb >= 2]
      ++ ["isolation" | c >= 4 && kb `notElem` ["SecureProcessingZone", "SecretZone", "DatabaseZone"]]
    bs = [b | b <- moBounds m, bFrom b == zName za, bTo b == zName zb]
    declared = concatMap (propNames "require" . bProps) bs
    exempt = concatMap (propNames "exempt" . bProps) bs
    union' xs ys = xs ++ [y | y <- nub ys, y `notElem` xs]

providedControls :: Ix -> FlowR -> [String]
providedControls ix f = nub (own ++ dst ++ egress ++ chan)
  where
    own = propNames "controls" (fProps f)
    dst = maybe [] (propNames "controls" . nProps) (M.lookup (fTo f) (ixNode ix))
    egress = maybe [] (propNames "egress_controls" . nProps) (M.lookup (fFrom f) (ixNode ix))
    chan = case propText "channel" (fProps f) of
      Just "tls" -> ["encryption", "integrity_check"]
      Just "mtls" -> ["encryption", "integrity_check", "authentication"]
      _ -> []

-- ---------------------------------------------------------------------------
-- Semantic diagnostics owned by the policy layer

policyDiags :: Ix -> Dom -> [RuleIR] -> [Diag]
policyDiags ix dom rs = concatMap check rs
  where
    check r
      | riEffect r == EfAllow, isJust (solve dom False (riCond r)), solve dom True (riCond r) == Nothing =
          let w = fromMaybe M.empty (solve dom False (riCond r))
              dn = maybe "?" (\v -> slotName ix "data" v) (M.lookup "data" w)
              an = maybe "?" (\v -> slotName ix "action" v) (M.lookup "action" w)
          in [ withHint ("add " ++ an ++ " to the operations of data type " ++ dn ++ ", or narrow the rule")
                 (withNode (riId r) (mkDiag SevError "TZ2005" (riPos r)
                   ("impossible permission: rule " ++ riId r ++ " allows " ++ an ++ " on " ++ dn ++ ", which the data type's operations list forbids"))) ]
      | otherwise = []

-- ---------------------------------------------------------------------------
-- Coverage

data Cov = Cov { cvFlow :: String, cvData :: String, cvRules :: [String], cvExplicit :: Bool }

policyCoverage :: Ix -> Dom -> [RuleIR] -> [Cov]
policyCoverage ix dom rs =
  [ Cov (fName f) d [riId r | r <- hits] (any (isTerminal . riEffect) hits)
  | f <- moFlows m, d <- fData f
  , let fixed = foldr andC CT
          ( [CEq "data" (dtId dr) | Just dr <- [M.lookup d (ixData ix)]]
         ++ [CEq "action" i | Just i <- [M.lookup (fOp f) (ixAction ix)]]
         ++ [CEq "res" (nId nr) | Just nr <- [M.lookup (fTo f) (ixNode ix)]]
         ++ [CEq "zone" (zId zr) | Just zr <- [nodeZone ix (fTo f)]] )
  , let hits = [r | r <- rs, isJust (solve dom True (andC (riCond r) fixed))] ]
  where m = ixModel ix

-- ---------------------------------------------------------------------------
-- Test generation

data TC = TC { tcName :: String, tcKind :: String, tcRule :: String, tcReq :: Assign, tcExp :: Decision }

genTests :: Ix -> Dom -> [RuleIR] -> [TC]
genTests ix dom rs = concatMap forRule rs
  where
    mk n k r a = TC n k (riId r) a (decide rs a)
    forRule r = pos r ++ neg r ++ bnd r ++ ctx r
    pos r = [mk ("positive/" ++ riId r) "positive" r w | Just w <- [solve dom True (riCond r)]]
    neg r = [mk ("negative/" ++ riId r) "negative" r w | Just w <- [solve dom True (notC (riCond r))]]
    bnd r = case solve dom True (riCond r) of
      Nothing -> []
      Just w -> take 6
        [ mk ("boundary/" ++ riId r ++ "/" ++ s ++ "=" ++ show v) "boundary" r a
        | at <- atomsOf (riCond r), (s, t) <- thresholds at, v <- [t, t - 1], a <- variant w s v ]
    ctx r = case solve dom True (riCond r) of
      Nothing -> []
      Just w -> [ mk ("context/" ++ riId r ++ "/" ++ s ++ "=" ++ show (1 - slotVal w s)) "context" r (M.insert s (1 - slotVal w s) w)
                | s <- ["mfa", "approved", "emergency", "secure", "tenant"], s `elem` ctxSlots ]
    ctxSlots = ["mfa", "approved", "emergency", "secure", "tenant"]
    thresholds a = case a of
      CGe s v -> [(s, v)]; CGt s v -> [(s, v + 1)]; CLe s v -> [(s, v + 1)]; CLt s v -> [(s, v)]
      _ -> []
    variant w s v = case M.lookup s (dDerivedOf dom) of
      Nothing -> [M.insert s v w]
      Just p -> [ assignSlot dom w p pv | pv <- take 1 [x | x <- cands dom True w p, derivedVal p s x == v] ]
    dDerivedOf _ = M.fromList [("class", "data"), ("ztrust", "zone")]
    derivedVal p s x = slotVal (assignSlot dom M.empty p x) s

-- ---------------------------------------------------------------------------
-- JSON

condJ :: Ix -> CExpr -> J
condJ _ = cexprJ

rulesJ :: Ix -> [RuleIR] -> J
rulesJ ix rs = arr
  [ obj
    [ ("idx", jint (riIdx r)), ("id", str (riId r)), ("policy", str (riPolicy r)), ("name", str (riName r))
    , ("effect", str (effectName (riEffect r))), ("terminal", jbool (isTerminal (riEffect r)))
    , ("cond", condJ ix (riCond r)), ("condText", str (cexprText ix (riCond r)))
    , ("reason", str (riReason r)), ("obligations", strs (map effectName (riObl r)))
    , ("obligationMask", jint (foldl' (.|.) 0 [effectBit e | e <- riObl r, not (isTerminal e)]))
    , ("priority", jint (riPrio r)), ("specificity", jint (riSpec r))
    , ("file", str (pFile (riPos r))), ("line", jint (pLine (riPos r))), ("version", str (riVersion r)) ]
  | r <- rs ]

decJ :: Decision -> J
decJ d = obj [("decision", jint (dcCode d)), ("reason", jint (dcReason d)), ("obligations", jint (dcObl d)), ("matched", ints (dcMatched d))]

assignJ :: Assign -> J
assignJ a = obj [(k, jint v) | (k, v) <- M.toList a]

testsJ :: [TC] -> J
testsJ = arr . map (\t -> obj [("name", str (tcName t)), ("kind", str (tcKind t)), ("rule", str (tcRule t)), ("request", assignJ (tcReq t)), ("expect", decJ (tcExp t))])

conflictsJ :: Ix -> [Conflict] -> J
conflictsJ ix = arr . map (\c -> obj
  [ ("kind", str (cfKind c)), ("severity", str (levelName (cfLevel c)))
  , ("allow", str (riId (cfAllow c))), ("deny", str (riId (cfDeny c))), ("winner", str (riId (cfWinner c)))
  , ("explain", str (cfExplain c)), ("witness", obj [(k, str (slotName ix k v)) | (k, v) <- M.toList (cfWitness c), k `elem` ["data", "zone", "res", "action", "roles", "class"]])
  , ("file", str (pFile (riPos (cfAllow c)))), ("line", jint (pLine (riPos (cfAllow c)))), ("denyLine", jint (pLine (riPos (cfDeny c)))) ])

optimizationsJ :: [Opt] -> J
optimizationsJ = arr . map (\o -> obj [("kind", str (opKind o)), ("rules", strs (opRules o)), ("message", str (opMsg o)), ("proposal", str (opProposal o)), ("file", str (pFile (opPos o))), ("line", jint (pLine (opPos o)))])

coverageJ :: [Cov] -> J
coverageJ = arr . map (\c -> obj [("flow", str (cvFlow c)), ("data", str (cvData c)), ("rules", strs (cvRules c)), ("covered", jbool (not (null (cvRules c)))), ("explicit", jbool (cvExplicit c))])

windowsJ :: Ix -> J
windowsJ ix = arr
  [ obj [ ("id", jint i), ("name", str (pdName w)), ("kind", str (fromMaybe "open" (propText "kind" (pdProps w))))
        , ("ranges", arr [ints [a, b] | (a, b) <- windowRanges (pdProps w)])
        , ("tz", str (fromMaybe (moTz (ixModel ix)) (propText "tz" (pdProps w)))) ]
  | (i, w) <- zip [0 :: Int ..] (moWindows (ixModel ix)) ]

symbolsJ :: Ix -> J
symbolsJ ix = obj
  [ ("roles", arr [obj [("name", str n), ("bit", jint (2 ^ i))] | (i, (n, _)) <- zip [0 :: Int ..] (moRoles m)])
  , ("zones", arr [obj [("id", jint (zId z)), ("name", str (zName z)), ("trust", jint (zTrust z)), ("kind", str (zKindS z)), ("kindId", jint (fromMaybe (-1) (lookup (zKindS z) (zip zoneKinds [0 ..])))), ("maxClass", maybe JNull (jint . fromMaybe 99 . flip M.lookup (ixClass ix)) (zMax z))] | z <- moZones m])
  , ("actions", arr [obj [("id", jint i), ("name", str n)] | (i, n) <- zip [0 :: Int ..] (allActions m)])
  , ("data", arr [obj [("id", jint (dtId d)), ("name", str (dtName d)), ("class", str (dtClass d)), ("rank", jint (dataRank ix (dtName d)))] | d <- moData m])
  , ("nodes", arr [obj [("id", jint (nId n)), ("name", str (nName n)), ("kind", str (kindName (nKind n))), ("zone", str (nZone n)), ("zoneId", jint (maybe (-1) zId (M.lookup (nZone n) (ixZone ix))))] | n <- moNodes m])
  , ("envs", arr [obj [("id", jint i), ("name", str n)] | (i, (n, _)) <- zip [0 :: Int ..] (moEnvs m)])
  , ("locations", arr [obj [("id", jint i), ("name", str n)] | (i, (n, _)) <- zip [0 :: Int ..] (moLocs m)])
  , ("classes", arr [obj [("name", str n), ("rank", jint r)] | (n, r) <- allClasses m])
  , ("zoneKinds", strs zoneKinds), ("nodeKinds", strs (map kindName [minBound .. maxBound]))
  , ("controls", arr [obj [("name", str c), ("bit", jint (controlBit c))] | c <- controlNames])
  , ("effects", arr [obj [("name", str (effectName e)), ("bit", jint (effectBit e)), ("terminal", jbool (isTerminal e))] | e <- [minBound .. maxBound]])
  , ("slots", strs slotNames) ]
  where m = ixModel ix

-- | Flat lookup tables baked into the WASM module's data section.
tablesJ :: Ix -> J
tablesJ ix = obj
  [ ("nz", jint nz), ("nc", jint nc), ("ng", jint 5), ("na", jint (length acts))
  , ("required", ints [ controlMask (requiredControls ix za zb c (repAction g))
                      | za <- zones, zb <- zones, c <- [0 .. nc - 1], g <- [0 .. 4 :: Int] ])
  , ("actionGroup", ints (map group acts))
  , ("zoneTrust", ints (map zTrust zones))
  , ("zoneMax", ints [maybe (-1) (fromMaybe (-1) . flip M.lookup (ixClass ix)) (zMax z) | z <- zones])
  , ("dataClass", ints [dataRank ix (dtName d) | d <- moData m])
  , ("dataOps", ints [maybe allBits opMask (getProp "operations" (dtProps d)) | d <- moData m])
  , ("dataExport", ints [maybe 0 exportCode (propText "export" (dtProps d)) | d <- moData m])
  , ("dataZone", ints [ if null zs then 1 else if zName z `elem` zs then 1 else 0
                      | d <- moData m, let zs = propNames "zones" (dtProps d), z <- zones ])
  , ("approvalBit", jint (controlBit "approval"))
  , ("exportAction", jint (fromMaybe (-1) (M.lookup "Export" (ixAction ix)))) ]
  where
    m = ixModel ix
    zones = moZones m
    nz = length zones
    nc = maximum (1 : map ((+ 1) . snd) (allClasses m))
    acts = allActions m
    group a = case a of
      "Export" -> 4; "Delete" -> 3; "Copy" -> 2
      _ | a `elem` ["Create", "Write", "Transform", "Enrich", "Publish"] -> 1
        | otherwise -> 0
    repAction g = case g of 4 -> "Export"; 3 -> "Delete"; 2 -> "Copy"; 1 -> "Write"; _ -> "Read"
    allBits = 2 ^ length acts - 1
    opMask v = sum [2 ^ i | n <- nub (valNames v), Just i <- [M.lookup n (ixAction ix)]]
    exportCode s = case s of "deny" -> 2; "approval" -> 1; _ -> 0 :: Int
