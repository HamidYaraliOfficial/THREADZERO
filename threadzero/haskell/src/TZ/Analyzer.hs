-- | Graph security analyzer: crossings, findings, control coverage, lineage,
--   dependencies, validation points, guards, assertions, constraints and properties.
module TZ.Analyzer
  ( Crossing(..), crossings, findings, verifyAll, Verified(..), controlCoverageJ, lineageJ
  , dependenciesJ, validationPointsJ, guardsJ, graphJ, metricsJ, findingJ, simplifierJ
  , findingsSorted, VerifyIn(..), runtimeChecksJ
  ) where

import Data.List (foldl', intercalate, nub, sortOn, (\\), sort, isInfixOf)
import qualified Data.Map.Strict as M
import Data.Maybe (fromMaybe, isJust, mapMaybe, listToMaybe)
import qualified Data.Set as S
import TZ.Expr
import TZ.Json
import TZ.Policy
import TZ.Semantic
import TZ.Solver
import TZ.Types

-- ---------------------------------------------------------------------------
-- Crossings

data Crossing = Crossing
  { crFlow :: FlowR, crData :: String, crRank :: Int, crFromZ :: ZoneR, crToZ :: ZoneR
  , crReq :: [String], crProv :: [String], crMissing :: [String] }

crossings :: Ix -> [Crossing]
crossings ix =
  [ Crossing f d r za zb req prov (req \\ prov)
  | f <- moFlows m, d <- fData f, Just za <- [nodeZone ix (fFrom f)], Just zb <- [nodeZone ix (fTo f)]
  , let r = M.findWithDefault 0 d eff
  , let req = requiredControls ix za zb r (fOp f)
  , let prov = providedControls ix f ]
  where m = ixModel ix
        eff = effClassOf ix

-- ---------------------------------------------------------------------------
-- Findings

baseF :: Finding
baseF = Finding "" "" LInfo 0.8 "" "" [] [] [] Nothing Nothing "" noPos []

baseLevel :: Int -> Level
baseLevel r | r >= 4 = LCritical | r == 3 = LHigh | r == 2 = LMedium | otherwise = LLow

lower :: Level -> Level
lower l = if l > LLow then pred l else l

findings :: Ix -> [RuleIR] -> [Conflict] -> [Finding]
findings ix rules confs = findingsSorted (concat
  [ ctlFindings, boundaryF, escapeF, privF, dbF, fanF, secretF, thirdF, confF, sodF, auditSame, plainF ])
  where
    m = ixModel ix
    eff = effClassOf ix
    rankOf d = M.findWithDefault (dataRank ix d) d eff
    flows = moFlows m
    cs = crossings ix
    zoneOf n = nodeZone ix n
    kindOf n = nKind <$> M.lookup n (ixNode ix)
    outOf n = [f | f <- flows, fFrom f == n]
    inOf n = [f | f <- flows, fTo f == n]

    -- shortest flow path helper
    bfs :: (FlowR -> Bool) -> String -> (String -> Bool) -> Maybe [FlowR]
    bfs ok start goal = go [(start, [])] (S.singleton start)
      where
        go [] _ = Nothing
        go ((n, path) : rest) seen
          | goal n && not (null path) = Just (reverse path)
          | otherwise =
              let nxt = [(fTo f, f : path) | f <- outOf n, ok f, fTo f `S.notMember` seen]
              in go (rest ++ nxt) (foldr (S.insert . fst) seen nxt)

    -- backwards path from a node to an origin (a node with no inbound flow carrying d)
    originPath d n = go [(n, [])] (S.singleton n)
      where
        go [] _ = []
        go ((x, path) : rest) seen =
          let ins = [f | f <- inOf x, d `elem` fData f]
          in if null ins then path
             else let nxt = [(fFrom f, f : path) | f <- ins, fFrom f `S.notMember` seen]
                  in if null nxt then path else go (rest ++ nxt) (foldr (S.insert . fst) seen nxt)

    flowPathNodes fs = case fs of [] -> []; (f : _) -> fFrom f : map fTo fs

    -- 1. missing controls -> categories
    byFlow = M.toList (M.fromListWith (++) [(fName (crFlow c), [c]) | c <- cs, not (null (crMissing c))])
    ctlFindings = concat
      [ concat
          [ mk "MissingAuthentication" "TZR-AUTHN-001" (baseLevel top) "Missing authentication on boundary crossing" ["authentication"] "add an authentication control (mTLS, token validation or an authenticating gateway) to the flow or its destination"
          , mk "MissingAuthorization" "TZR-AUTHZ-001" (baseLevel top) "Missing authorization on boundary crossing" ["authorization"] "enforce an authorization check (policy guard) before the destination processes the data"
          , mk "UnvalidatedInputPath" "TZR-VAL-001" (baseLevel top) "Unvalidated input path" ["schema_validation", "input_validation"] "validate and sanitize input at the boundary (schema + input validation guard)"
          , mk "MissingAudit" "TZR-AUDIT-001" (lower (baseLevel top)) "Missing audit trail on boundary crossing" ["audit"] "emit an immutable audit event for this crossing"
          , mk "SecurityControlGap" "TZR-CTL-001" (lower (baseLevel top)) "Security control gap on boundary crossing"
              (filter (`notElem` ["authentication", "authorization", "schema_validation", "input_validation", "audit"]) allMissing)
              "add the missing controls to the flow, or route it through an enforcement gateway" ]
      | (fn, xs) <- byFlow, let f = crFlow (head xs), let top = maximum (map crRank xs)
      , let allMissing = nub (concatMap crMissing xs)
      , let topData = crData (head (sortOn (negate . crRank) xs))
      , let za = crFromZ (head xs); zb = crToZ (head xs)
      , let mk cat rid lvl title wanted fix =
              [ baseF { fnCat = cat, fnRule = rid, fnLevel = lvl, fnConf = 0.9, fnTitle = title
                      , fnMsg = "Flow " ++ fn ++ " (" ++ fFrom f ++ " -> " ++ fTo f ++ ") crosses from " ++ zName za ++ " to " ++ zName zb ++ " carrying " ++ topData ++ " but lacks: " ++ intercalate ", " miss
                      , fnEvidence = ["required controls: " ++ intercalate ", " (nub (concatMap crReq xs)), "provided controls: " ++ intercalate ", " (nub (concatMap crProv xs))]
                      , fnPath = [fFrom f, fTo f], fnAffected = [fFrom f, fTo f], fnFlow = Just fn, fnData = Just topData
                      , fnFix = fix, fnPos = fPos f, fnMissing = miss }
              | let miss = filter (`elem` allMissing) wanted, not (null miss)] ]

    -- 2. implicit trust-boundary violation (no explicit max_class)
    boundaryF =
      [ baseF { fnCat = "TrustBoundaryViolation", fnRule = "TZR-TBV-001", fnLevel = baseLevel r, fnConf = 0.85
              , fnTitle = "Data classification exceeds destination zone trust"
              , fnMsg = "Flow " ++ fName f ++ " moves " ++ d ++ " (" ++ className ix r ++ ") into zone " ++ zName z ++ " with trust level " ++ show (zTrust z)
              , fnEvidence = ["classification rank " ++ show r ++ " > zone trust " ++ show (zTrust z), "declare max_class on the zone if this is intentional"]
              , fnPath = [fFrom f, fTo f], fnAffected = [fFrom f, fTo f], fnFlow = Just (fName f), fnData = Just d
              , fnFix = "keep the data inside a zone with sufficient trust, tokenize it before it crosses, or set an explicit max_class on the zone", fnPos = fPos f }
      | f <- flows, d <- fData f, Just z <- [zoneOf (fTo f)], zMax z == Nothing, let r = rankOf d, r >= 2, zTrust z < r, kindOf (fFrom f) /= Just KSecret ]

    -- 3. sensitive data escape
    lowZone z = zKindS z `elem` ["PublicInternet", "UntrustedZone", "ThirdPartyZone", "PartnerZone"] || zTrust z <= 1
    escapeF = nub' [ fnKey f' f' | f' <- raw ]
      where
        raw =
          [ baseF { fnCat = "SensitiveDataEscape", fnRule = "TZR-ESC-001", fnLevel = if r >= 4 then LCritical else LHigh, fnConf = 0.8
                  , fnTitle = "Sensitive data escapes to a low-trust zone"
                  , fnMsg = d ++ " (" ++ className ix r ++ ") reaches " ++ fTo f ++ " in low-trust zone " ++ zName z ++ " via " ++ intercalate " -> " (map fName full)
                  , fnEvidence = ["path: " ++ intercalate " -> " (flowPathNodes full), "no declassification or tokenization on the path"]
                  , fnPath = flowPathNodes full, fnAffected = nub (flowPathNodes full), fnFlow = Just (fName f), fnData = Just d
                  , fnFix = "tokenize or redact before the boundary, or keep processing inside a secure zone", fnPos = fPos f }
          | f <- flows, d <- fData f, let r = rankOf d, r >= 3, Just z <- [zoneOf (fTo f)], lowZone z
          , maybe True (\mc -> M.findWithDefault 99 mc (ixClass ix) < r) (zMax z)
          , let full = originPath d (fFrom f) ++ [f] ]
        fnKey _ f = f
        nub' = foldr (\x acc -> if any (\y -> fnCat y == fnCat x && fnFlow y == fnFlow x && fnData y == fnData x) acc then acc else x : acc) []

    -- 4. excessive privilege
    wide r = not (any (`elem` ["res", "data", "action", "class", "zone", "rzone", "reskind"]) (slotsOf (riCond r)))
    privF =
      [ baseF { fnCat = "ExcessivePrivilege", fnRule = "TZR-PRIV-001", fnLevel = LHigh, fnConf = 0.75
              , fnTitle = "Allow rule without resource, action or data restriction"
              , fnMsg = "Rule " ++ riId' r ++ " allows every action on every resource for matching subjects"
              , fnEvidence = ["condition: " ++ cexprText ix (riCond r)], fnAffected = [riPolicy r], fnFix = "restrict the rule with resource, action or data.classification conditions", fnPos = riPos r }
      | r <- rules, riEffect r == EfAllow, wide r ] ++
      [ baseF { fnCat = "ExcessivePrivilege", fnRule = "TZR-PRIV-002", fnLevel = LMedium, fnConf = 0.85
              , fnTitle = "Node receives data above its clearance"
              , fnMsg = nName n ++ " has clearance " ++ cl ++ " but receives " ++ d ++ " (" ++ className ix (rankOf d) ++ ") via " ++ fName f
              , fnEvidence = ["clearance rank " ++ show cr ++ " < data rank " ++ show (rankOf d)], fnPath = [fFrom f, fTo f], fnAffected = [nName n], fnFlow = Just (fName f), fnData = Just d
              , fnFix = "split the node so that high-classification data is handled by a separate, higher-clearance component", fnPos = fPos f }
      | f <- flows, d <- fData f, Just n <- [M.lookup (fTo f) (ixNode ix)], Just cl <- [propText "clearance" (nProps n)]
      , Just cr <- [M.lookup cl (ixClass ix)], rankOf d > cr ] ++
      [ baseF { fnCat = "ExcessivePrivilege", fnRule = "TZR-PRIV-003", fnLevel = LLow, fnConf = 0.6, fnTitle = "Identity holds many roles"
              , fnMsg = i ++ " holds " ++ show (length rs) ++ " roles: " ++ unwords rs, fnAffected = [i], fnFix = "review role assignments and remove unused roles", fnPos = noPos }
      | (i, rs) <- M.toList (M.fromListWith (++) [(a, [b]) | (a, b, _) <- moAssigns m]), length rs >= 3 ]
    riId' r = riPolicy r ++ "." ++ riName r

    -- 5. direct database access
    dbF =
      [ baseF { fnCat = "DirectDatabaseAccess", fnRule = "TZR-DB-001", fnLevel = baseLevel top', fnConf = 0.9, fnTitle = "Direct database access"
              , fnMsg = "Flow " ++ fName f ++ " connects " ++ fFrom f ++ " (" ++ kindName ka ++ ") and " ++ fTo f ++ " (" ++ kindName kb ++ ") directly, bypassing the service tier of database " ++ dbn
              , fnEvidence = ["endpoint kinds: " ++ kindName ka ++ " -> " ++ kindName kb], fnPath = [fFrom f, fTo f], fnAffected = [fFrom f, fTo f], fnFlow = Just (fName f), fnData = listToMaybe (fData f)
              , fnFix = "introduce a repository/data-access service that owns the database connection", fnPos = fPos f }
      | f <- flows, Just ka <- [kindOf (fFrom f)], Just kb <- [kindOf (fTo f)]
      , (ka == KDatabase && kb `elem` direct) || (kb == KDatabase && ka `elem` direct)
      , let dbn = if ka == KDatabase then fFrom f else fTo f
      , let top' = maximum (0 : map rankOf (fData f)) ]
      where direct = [KUser, KIdentity, KApplication, KExternal, KAgent, KDevice]

    -- 6. fan-out
    fanF =
      [ baseF { fnCat = "UnsafeDataFanOut", fnRule = "TZR-FAN-001", fnLevel = LMedium, fnConf = 0.7, fnTitle = "Unsafe data fan-out"
              , fnMsg = d ++ " fans out from " ++ n ++ " to " ++ show (length dests) ++ " destinations across " ++ show (length zs) ++ " zones"
              , fnEvidence = ["destinations: " ++ unwords dests, "zones: " ++ unwords zs], fnPath = n : dests, fnAffected = n : dests, fnData = Just d
              , fnFix = "distribute through a single policy-enforcing broker with per-consumer minimization", fnPos = maybe noPos nPos (M.lookup n (ixNode ix)) }
      | d <- map dtName (moData m), rankOf d >= 2, n <- map nName (moNodes m)
      , let dests = nub [fTo f | f <- outOf n, d `elem` fData f]
      , let zs = nub [zName z | t <- dests, Just z <- [zoneOf t]]
      , length dests >= 4 || length zs >= 3 ]

    -- 7. secret exposure
    secretF =
      [ baseF { fnCat = "SecretExposurePath", fnRule = "TZR-SEC-001", fnLevel = LCritical, fnConf = 0.9, fnTitle = "Secret exposure path"
              , fnMsg = "Flow " ++ fName f ++ " exposes " ++ d ++ " (" ++ className ix (rankOf d) ++ ") " ++ why
              , fnEvidence = [why], fnPath = [fFrom f, fTo f], fnAffected = [fFrom f, fTo f], fnFlow = Just (fName f), fnData = Just d
              , fnFix = "never log or forward secrets; resolve them at the point of use inside a secret zone", fnPos = fPos f }
      | f <- flows, d <- fData f, rankOf d >= 5
      , Just kb <- [kindOf (fTo f)], Just zb <- [zoneOf (fTo f)]
      , let why | fOp f == "Log" = "to a log sink"
                | kb `elem` [KExternal, KUser, KApplication, KQueue, KFileStore] || zTrust zb < 3 = "to " ++ kindName kb ++ " " ++ fTo f ++ " outside a trusted secret path"
                | otherwise = ""
      , not (null why) ] ++
      [ baseF { fnCat = "SensitiveDataEscape", fnRule = "TZR-ESC-002", fnLevel = LHigh, fnConf = 0.85, fnTitle = "Forbidden data written to a log"
              , fnMsg = d ++ " must not be logged (logging: forbidden) but flow " ++ fName f ++ " logs it", fnPath = [fFrom f, fTo f], fnAffected = [fFrom f, fTo f], fnFlow = Just (fName f), fnData = Just d
              , fnFix = "redact the data before logging or remove the Log flow", fnPos = fPos f }
      | f <- flows, fOp f == "Log", d <- fData f, rankOf d < 5, Just dr <- [M.lookup d (ixData ix)], propText "logging" (dtProps dr) == Just "forbidden" ]

    -- 8. third-party
    third z = zKindS z `elem` ["ThirdPartyZone", "PartnerZone"]
    thirdF =
      [ baseF { fnCat = "UncontrolledThirdPartyFlow", fnRule = "TZR-3P-001", fnLevel = if top >= 3 then LHigh else LMedium, fnConf = 0.85
              , fnTitle = "Uncontrolled third-party data flow"
              , fnMsg = "Flow " ++ fName f ++ " exchanges " ++ topData ++ " with third-party/partner party lacking: " ++ intercalate ", " miss
              , fnEvidence = ["missing controls: " ++ intercalate ", " miss], fnPath = [fFrom f, fTo f], fnAffected = [fFrom f, fTo f], fnFlow = Just (fName f), fnData = Just topData
              , fnFix = "route through an egress gateway with minimization/redaction, approval and audit", fnPos = fPos f }
      | (fn, xs) <- byFlow, let f = crFlow (head xs), let za = crFromZ (head xs), let zb = crToZ (head xs)
      , third za || third zb || kindOf (fFrom f) == Just KExternal || kindOf (fTo f) == Just KExternal
      , let miss = nub [c | x <- xs, c <- crMissing x, c `elem` ["audit", "data_minimization", "redaction", "approval", "token_exchange"]]
      , not (null miss), let top = maximum (map crRank xs), let topData = crData (head (sortOn (negate . crRank) xs)), let _ = fn ]

    -- 9. policy conflicts
    confF =
      [ baseF { fnCat = "PolicyConflict", fnRule = "TZR-POL-001", fnLevel = cfLevel c, fnConf = 0.8, fnTitle = cfKind c
              , fnMsg = cfExplain c, fnAffected = [riPolicy (cfAllow c), riPolicy (cfDeny c)], fnEvidence = [cfExplain c]
              , fnFix = "give the rules distinct priorities/scopes or narrow their conditions so intent is explicit", fnPos = riPos (cfAllow c) }
      | c <- confs, cfLevel c >= LMedium ]

    -- 10. separation of duties
    holders r = nub ([a | (a, b, _) <- moAssigns m, b == r] ++ [t | d <- moDelegs m, propNames "role" (pdProps d) == [r], not (propBool "revoked" False (pdProps d)), t <- propNames "to" (pdProps d)])
    sodF =
      [ baseF { fnCat = "SeparationOfDutiesViolation", fnRule = "TZR-SOD-001", fnLevel = LHigh, fnConf = 0.95, fnTitle = "Separation of duties violated"
              , fnMsg = i ++ " holds conflicting roles " ++ a ++ " and " ++ b ++ " (" ++ pdName s ++ ")", fnAffected = [i]
              , fnEvidence = ["roles: " ++ a ++ ", " ++ b], fnFix = "assign the roles to different identities and revoke the delegation that merges them", fnPos = pdPos s }
      | s <- moSeps m, [a, b] <- [take 2 (propNames "roles" (pdProps s))], i <- holders a, i `elem` holders b ]

    -- 11. audit on same-zone destructive ops
    auditSame =
      [ baseF { fnCat = "MissingAudit", fnRule = "TZR-AUDIT-002", fnLevel = LMedium, fnConf = 0.8, fnTitle = "Destructive or export operation without audit"
              , fnMsg = "Flow " ++ fName f ++ " performs " ++ fOp f ++ " without an audit control", fnPath = [fFrom f, fTo f], fnAffected = [fFrom f, fTo f], fnFlow = Just (fName f), fnData = listToMaybe (fData f)
              , fnFix = "add the audit control", fnPos = fPos f, fnMissing = ["audit"] }
      | f <- flows, fOp f `elem` ["Export", "Delete"], "audit" `notElem` providedControls ix f
      , not (any (\c -> fName (crFlow c) == fName f && "audit" `elem` crMissing c) cs) ]

    -- 12. plain channel carrying sensitive data
    plainF =
      [ baseF { fnCat = "SecurityControlGap", fnRule = "TZR-CTL-002", fnLevel = LMedium, fnConf = 0.85, fnTitle = "Sensitive data over a plain channel"
              , fnMsg = "Flow " ++ fName f ++ " carries " ++ d ++ " over channel 'plain'", fnPath = [fFrom f, fTo f], fnAffected = [fFrom f, fTo f], fnFlow = Just (fName f), fnData = Just d
              , fnFix = "use tls or mtls", fnPos = fPos f, fnMissing = ["encryption"] }
      | f <- flows, propText "channel" (fProps f) == Just "plain", d <- fData f, rankOf d >= 3
      , not (any (\c -> fName (crFlow c) == fName f && "encryption" `elem` crMissing c) cs) ]

findingsSorted :: [Finding] -> [Finding]
findingsSorted fs = sortOn (\f -> (negate (fromEnum (fnLevel f)), fnCat f, fingerprint f, fnRule f)) (dedup fs)
  where dedup = foldr (\x acc -> if any (\y -> fingerprint y == fingerprint x && fnRule y == fnRule x && fnMsg y == fnMsg x) acc then acc else x : acc) []

findingJ :: Int -> Finding -> J
findingJ i f = obj
  [ ("id", str ("F-" ++ pad3 (i + 1))), ("category", str (fnCat f)), ("ruleId", str (fnRule f)), ("severity", str (levelName (fnLevel f)))
  , ("confidence", jnum (fnConf f)), ("title", str (fnTitle f)), ("message", str (fnMsg f)), ("evidence", strs (fnEvidence f))
  , ("path", strs (if null (fnPath f) then fnAffected f else fnPath f)), ("affected", strs (fnAffected f)), ("flow", jmaybe str (fnFlow f)), ("data", jmaybe str (fnData f))
  , ("violatedRule", str (fnRule f ++ ": " ++ fnTitle f)), ("suggestedFix", str (fnFix f)), ("missing", strs (fnMissing f))
  , ("fingerprint", str (fingerprint f)), ("file", str (pFile (fnPos f))), ("line", jint (pLine (fnPos f))), ("col", jint (pCol (fnPos f))) ]
  where pad3 n = let s = show n in replicate (3 - length s) '0' ++ s

-- ---------------------------------------------------------------------------
-- Verification: assertions, constraints, properties

data VerifyIn = VerifyIn { viRules :: [RuleIR], viDom :: Dom }

data Verified = Verified
  { vAssertions :: J, vConstraints :: J, vProperties :: J, vObligations :: J, vDiags :: [Diag], vAssertDiags :: [Diag] }

verifyAll :: Ix -> VerifyIn -> [Finding] -> Verified
verifyAll ix vi fs = Verified assertJ constrJ propJ oblJ constrDiags assertDiags
  where
    m = ixModel ix
    eff = effClassOf ix
    rankOf d = M.findWithDefault (dataRank ix d) d eff
    flows = moFlows m
    zoneOf n = zName <$> nodeZone ix n
    prov = providedControls ix

    assertRes = [ (a, evalAssert (asBody a)) | a <- moAsserts m ]
    -- (status, method, evidence)
    evalAssert :: Assertion -> (String, String, [String])
    evalAssert a = case a of
      AsNeverEnter d z ->
        let bad = [fName f | f <- flows, d `elem` fData f, zoneOf (fTo f) == Just z] ++ [nName n | n <- moNodes m, nZone n == z, d `elem` propNames "stores" (nProps n)]
        in verdict bad "static-graph"
      AsMustNot x o y -> verdict [fName f | f <- flows, fFrom f == x, fTo f == y, fOp f == o] "static-graph"
      AsActionAudit o -> verdict [fName f | f <- flows, fOp f == o, "audit" `notElem` prov f] "static-graph"
      AsNodeControl n c ->
        let own = maybe [] (propNames "controls" . nProps) (M.lookup n (ixNode ix))
            ins = [f | f <- flows, fTo f == n]
        in if c `elem` own then ("discharged", "static-graph", ["node " ++ n ++ " declares control " ++ c])
           else verdict [fName f | f <- ins, c `notElem` prov f] "static-graph" `orIfNoInbound` (null ins, n, c)
      AsSecureChannel (Just f) -> verdict [fName x | x <- flows, fName x == f, propText "channel" (fProps x) `notElem` [Just "tls", Just "mtls"]] "static-graph"
      AsSecureChannel Nothing -> verdict [fName x | x <- flows, Just za <- [zoneOf (fFrom x)], Just zb <- [zoneOf (fTo x)], za /= zb, propText "channel" (fProps x) `notElem` [Just "tls", Just "mtls"]] "static-graph"
      AsNeverOp (Left d) o -> verdict [fName f | f <- flows, d `elem` fData f, fOp f == o] "static-graph"
      AsNeverOp (Right c) o -> let r = M.findWithDefault 0 c (ixClass ix) in verdict [fName f | f <- flows, fOp f == o, any ((>= r) . rankOf) (fData f)] "static-graph"
      AsRequest e want -> requestProof e want
    orIfNoInbound (s, meth, ev) (noIn, n, c) = if noIn then ("violated", meth, ["node " ++ n ++ " has no control " ++ c ++ " and no inbound flow provides it"]) else (s, meth, ev)
    verdict bad meth = if null bad then ("discharged", meth, ["no violating flow or node in the model"]) else ("violated", meth, ["violating flows/nodes: " ++ unwords (take 8 bad)])

    requestProof e want = case resolveExpr ix noPos e of
      Left d -> ("violated", "type-check", [dMsg d])
      Right ce ->
        let dom = viDom vi
            rs = viRules vi
            allSlots = orderSlots (primaries dom (nub (slotsOf ce ++ concatMap (slotsOf . riCond) rs)))
            wantCode = if want == EfDeny then 0 else 1 :: Int
            cap = 4000
            counter xs = [a | a <- xs, dcCode (decide rs a) /= wantCode]
            cex a = intercalate ", " [k ++ "=" ++ slotName ix k v | (k, v) <- M.toList a, k `elem` ["data", "zone", "res", "action", "roles", "class", "mfa"]]
            allows = [r | r <- rs, riEffect r == EfAllow]
        in if want == EfDeny && all (\r -> solve dom True (andC ce (riCond r)) == Nothing) allows
             then ("discharged", "solver-unsat", ["no allow rule can match any request satisfying the condition (proved by unsatisfiability), so the default deny always applies"])
             else
               let cands' = take cap (enumSat dom True allSlots ce)
               in case counter cands' of
                    (a : _) -> ("violated", "bounded-enumeration", ["counterexample: " ++ cex a])
                    [] | length cands' < cap -> ("discharged", "bounded-enumeration", ["all " ++ show (length cands') ++ " modelled requests satisfying the condition are " ++ effectName want ++ "ed"])
                       | otherwise -> ("runtime", "runtime-check", ["state space exceeds the static proof bound; enforced at runtime and by generated property tests"])

    runtimeKind a = case a of
      AsRequest _ _ -> "property-test"
      AsNodeControl _ _ -> "none"
      _ -> "validate_flow"

    assertJ = arr [ obj [ ("name", str (asName a)), ("text", str (show' (asBody a))), ("status", str s), ("method", str meth), ("evidence", strs ev)
                        , ("runtime", str (runtimeKind (asBody a))), ("file", str (pFile (asPos a))), ("line", jint (pLine (asPos a))) ]
                  | (a, (s, meth, ev)) <- assertRes ]
    show' a = case a of
      AsNeverEnter d z -> "never data " ++ d ++ " enters zone " ++ z
      AsMustNot x o y -> x ++ " must_not " ++ o ++ " " ++ y
      AsActionAudit o -> "action " ++ o ++ " must audit"
      AsNodeControl n c -> n ++ " must_have " ++ c
      AsSecureChannel (Just f) -> "flow " ++ f ++ " must secure_channel"
      AsSecureChannel Nothing -> "all flows must secure_channel"
      AsNeverOp (Left d) o -> "never data " ++ d ++ " op " ++ o
      AsNeverOp (Right c) o -> "never class " ++ c ++ " op " ++ o
      AsRequest _ w -> "request <condition> must " ++ effectName w

    assertDiags = [ withNode (asName a) ((mkDiag SevFinding "TZR-ASSERT-001" (asPos a) ("assertion '" ++ asName a ++ "' is violated: " ++ intercalate "; " ev)) { dHint = Just "fix the architecture or the assertion; violated assertions fail CI" }) | (a, ("violated", _, ev)) <- assertRes ]

    -- constraints
    fanout d = maximum (0 : [length (nub [fTo f | f <- flows, fFrom f == n, d `elem` fData f]) | n <- map nName (moNodes m)])
    cycleExists = any (\p -> go [plName p] p) (moPolicies m)
      where go seen p = case plExtends p >>= \e -> M.lookup e (ixPolicy ix) of
              Nothing -> False
              Just q -> plName q `elem` seen || go (plName q : seen) q
    cEval c = case c of
      CoMaxClass z k ->
        let r = M.findWithDefault 99 k (ixClass ix)
            bad = [d ++ " in " ++ nName n | n <- moNodes m, nZone n == z, d <- propNames "stores" (nProps n), rankOf d > r]
                  ++ [d ++ " via " ++ fName f | f <- flows, zoneOf (fTo f) == Just z, d <- fData f, rankOf d > r]
        in (null bad, bad)
      CoNoFlow a b md ->
        let bad = [fName f | f <- flows, zoneOf (fFrom f) == Just a, zoneOf (fTo f) == Just b, maybe True (`elem` fData f) md]
        in (null bad, bad)
      CoRequireControl k a b ->
        let bad = [fName f | f <- flows, zoneOf (fFrom f) == Just a, zoneOf (fTo f) == Just b, k `notElem` prov f]
        in (null bad, bad)
      CoMaxFanout d n -> (fanout d <= n, ["fan-out of " ++ d ++ " is " ++ show (fanout d) ++ " (limit " ++ show n ++ ")" | fanout d > n])
      CoAcyclicPolicies -> (not cycleExists, ["policy inheritance contains a cycle" | cycleExists])
    constrRes = [(c, cEval (csBody c)) | c <- moConstraints m]
    constrDiags = [ withNode (csName c) (mkDiag SevError "TZ2008" (csPos c) ("unsatisfied constraint '" ++ csName c ++ "': " ++ intercalate "; " (take 5 ev))) | (c, (False, ev)) <- constrRes ]
    constrJ = arr [ obj [("name", str (csName c)), ("satisfied", jbool ok), ("evidence", strs (take 8 ev)), ("file", str (pFile (csPos c))), ("line", jint (pLine (csPos c)))] | (c, (ok, ev)) <- constrRes ]

    -- properties
    propMap =
      [ ("Confidentiality", ["SensitiveDataEscape", "SecretExposurePath", "TrustBoundaryViolation", "UncontrolledThirdPartyFlow"], ["encryption", "redaction"])
      , ("Integrity", ["UnvalidatedInputPath"], ["integrity_check", "schema_validation"])
      , ("Authenticity", ["MissingAuthentication"], ["token_exchange"])
      , ("LeastPrivilege", ["ExcessivePrivilege", "DirectDatabaseAccess"], [])
      , ("SeparationOfDuties", ["SeparationOfDutiesViolation"], [])
      , ("Traceability", ["MissingAudit"], [])
      , ("DataMinimization", ["UnsafeDataFanOut"], ["data_minimization"])
      , ("BoundaryEnforcement", ["MissingAuthorization", "SecurityControlGap", "PolicyConflict", "TrustBoundaryViolation"], []) ]
    enabled n = case [b | (k, b, _) <- moPropsOn m, k == n] of (b : _) -> b; [] -> True
    idOf i = "F-" ++ (let s = show (i + 1) in replicate (3 - length s) '0' ++ s)
    failedAsserts = [asName a | (a, ("violated", _, _)) <- assertRes]
    failedConstraints = [csName c | (c, (False, _)) <- constrRes]
    propJ = arr
      [ obj [ ("name", str n), ("enabled", jbool (enabled n))
            , ("status", str (if not (enabled n) then "disabled" else if null hit && (n /= "BoundaryEnforcement" || (null failedAsserts && null failedConstraints)) then "holds" else "violated"))
            , ("findings", strs [idOf i | (i, _) <- hit]), ("discharge", str (if n == "BoundaryEnforcement" then "static + runtime (validate_boundary)" else "static graph analysis"))
            , ("failedAssertions", strs (if n == "BoundaryEnforcement" then failedAsserts else [])) ]
      | (n, cats, ctl) <- propMap
      , let hit = [(i, f) | (i, f) <- zip [0 :: Int ..] fs, fnCat f `elem` cats || (fnCat f == "SecurityControlGap" && any (`elem` ctl) (fnMissing f))] ]
    oblJ = arr $
      [ obj [("id", str ("OBL-A-" ++ asName a)), ("statement", str (show' (asBody a))), ("status", str s), ("method", str meth)] | (a, (s, meth, _)) <- assertRes ] ++
      [ obj [("id", str "OBL-RT-1"), ("statement", str "every dynamic request must pass authorize() before reaching a protected resource"), ("status", str "runtime"), ("method", str "runtime-guard")]
      , obj [("id", str "OBL-RT-2"), ("statement", str "every flow not present in the model must pass validate_flow()"), ("status", str "runtime"), ("method", str "runtime-guard")] ]

-- | Assertions lowered to runtime checks for validate_flow (WASM).
runtimeChecksJ :: Ix -> J
runtimeChecksJ ix = arr (concatMap one (zip [0 :: Int ..] (moAsserts m)))
  where
    m = ixModel ix
    nid n = maybe (-1) nId (M.lookup n (ixNode ix))
    did d = maybe (-1) dtId (M.lookup d (ixData ix))
    zid z = maybe (-1) zId (M.lookup z (ixZone ix))
    act a = fromMaybe (-1) (M.lookup a (ixAction ix))
    one (i, a) = case asBody a of
      AsNeverEnter d z -> [chk "never_enter" [("data", did d), ("zone", zid z)]]
      AsMustNot x o y -> [chk "must_not" [("subj", nid x), ("action", act o), ("res", nid y)]]
      AsActionAudit o -> [chk "require_control" [("action", act o), ("control", controlBit "audit")]]
      AsSecureChannel (Just f) -> [chk "secure_flow" [("subj", maybe (-1) (nid . fFrom) (M.lookup f (ixFlow ix))), ("res", maybe (-1) (nid . fTo) (M.lookup f (ixFlow ix)))]]
      AsSecureChannel Nothing -> [chk "secure_crossing" []]
      AsNeverOp (Left d) o -> [chk "never_op" [("data", did d), ("action", act o)]]
      AsNeverOp (Right c) o -> [chk "never_class_op" [("rank", M.findWithDefault 99 c (ixClass ix)), ("action", act o)]]
      _ -> []
      where chk k ps = obj ([("id", jint i), ("name", str (asName a)), ("kind", str k)] ++ [(x, jint y) | (x, y) <- ps])

-- ---------------------------------------------------------------------------
-- Control coverage, lineage, dependencies, validation points, guards, graph, metrics

ctlGroups :: [(String, [String])]
ctlGroups =
  [ ("Authentication", ["authentication", "mfa", "token_exchange"]), ("Authorization", ["authorization"])
  , ("Encryption", ["encryption", "integrity_check"]), ("Validation", ["schema_validation", "input_validation", "output_filtering"])
  , ("Audit", ["audit"]), ("Monitoring", ["monitoring"]), ("Approval", ["approval"]), ("Isolation", ["isolation", "redaction", "data_minimization", "tokenization"]) ]

controlCoverageJ :: Ix -> J
controlCoverageJ ix = arr
  [ obj [ ("flow", str (fName f)), ("from", str (fFrom f)), ("to", str (fTo f))
        , ("crossing", jbool (any (\c -> fName (crFlow c) == fName f && zName (crFromZ c) /= zName (crToZ c)) cs))
        , ("controls", obj [ (g, str (status g members)) | (g, members) <- ctlGroups ]) ]
  | f <- moFlows (ixModel ix)
  , let mine = [c | c <- cs, fName (crFlow c) == fName f]
  , let status _ members =
          let req = any (\c -> any (`elem` crReq c) members) mine
              got = any (\x -> x `elem` providedControls ix f) members
          in if req && got then "satisfied" else if req then "missing" else if got then "extra" else "n/a" ]
  where cs = crossings ix

lineageJ :: Ix -> J
lineageJ ix = arr
  [ obj [ ("data", str d), ("class", str (dtClass dr)), ("effectiveClass", str (className ix (M.findWithDefault 0 d eff)))
        , ("origins", strs origins), ("stores", strs (nub ([nName n | n <- moNodes m, d `elem` propNames "stores" (nProps n)] ++ [fTo f | f <- fl, kindOf (fTo f) `elem` [Just KDatabase, Just KFileStore]])))
        , ("flows", arr [flowJ f | f <- fl])
        , ("journeys", arr [journeyJ p | p <- take 40 paths])
        , ("derivedFrom", strs (propNames "derived_from" (dtProps dr)))
        , ("declassifications", arr [obj [("name", str (pdName x)), ("via", strs (propNames "via" (pdProps x))), ("approval", strs (propNames "approval" (pdProps x))), ("produces", strs (propNames "produces" (pdProps x)))] | x <- moDeclass m, d `elem` propNames "data" (pdProps x)]) ]
  | dr <- moData m, let d = dtName dr
  , let fl = [f | f <- moFlows m, d `elem` fData f]
  , let origins = nub [fFrom f | f <- fl, all (\g -> fTo g /= fFrom f) fl]
  , let paths = concat [walk fl [] o | o <- origins] ]
  where
    m = ixModel ix
    eff = effClassOf ix
    kindOf n = nKind <$> M.lookup n (ixNode ix)
    flowJ f = obj [("flow", str (fName f)), ("from", str (fFrom f)), ("to", str (fTo f)), ("op", str (fOp f)), ("step", jint (propInt "step" 0 (fProps f))), ("version", str (maybe "1" showV (getProp "version" (fProps f))))
                  , ("fromZone", jmaybe (str . zName) (nodeZone ix (fFrom f))), ("toZone", jmaybe (str . zName) (nodeZone ix (fTo f)))
                  , ("controls", strs (providedControls ix f))]
    showV v = case v of VNum n -> show n; VStr s -> s; VId s -> s; _ -> "1"
    walk fl seen n = let outs = [f | f <- fl, fFrom f == n, fName f `notElem` seen]
                     in if null outs || length seen >= 8 then [reverse seen | not (null seen)]
                        else concat [walk fl (fName f : seen) (fTo f) | f <- outs]
    journeyJ p = arr [ obj [ ("flow", str fn), ("crossing", jbool (maybe False (\f -> fmap zName (nodeZone ix (fFrom f)) /= fmap zName (nodeZone ix (fTo f))) (M.lookup fn (ixFlow ix)))) ] | fn <- p ]

dependenciesJ :: Ix -> [RuleIR] -> J
dependenciesJ ix rules = arr [ obj [("from", str a), ("to", str b), ("kind", str k)] | (a, b, k) <- nub edges ]
  where
    m = ixModel ix
    edges =
      [ ("node:" ++ nName n, "zone:" ++ nZone n, "in-zone") | n <- moNodes m ] ++
      [ ("flow:" ++ fName f, "node:" ++ fFrom f, "source") | f <- moFlows m ] ++
      [ ("flow:" ++ fName f, "node:" ++ fTo f, "sink") | f <- moFlows m ] ++
      [ ("flow:" ++ fName f, "data:" ++ d, "carries") | f <- moFlows m, d <- fData f ] ++
      [ ("data:" ++ dtName d, "zone:" ++ z, "allowed-in") | d <- moData m, z <- propNames "zones" (dtProps d) ] ++
      [ ("data:" ++ dtName d, "data:" ++ s, "derived-from") | d <- moData m, s <- propNames "derived_from" (dtProps d) ] ++
      [ ("policy:" ++ riPolicy r, ent, "references") | r <- rules, ent <- refsOf (riCond r) ] ++
      [ ("policy:" ++ plName p, "policy:" ++ e, "extends") | p <- moPolicies m, Just e <- [plExtends p] ] ++
      [ ("assertion:" ++ asName a, "data:" ++ d, "asserts") | a <- moAsserts m, AsNeverEnter d _ <- [asBody a] ]
    refsOf c = concat [ case a of
        CEq "zone" v -> ["zone:" ++ slotName ix "zone" v]
        CEq "res" v -> ["node:" ++ slotName ix "res" v]
        CEq "data" v -> ["data:" ++ slotName ix "data" v]
        CHas "roles" v -> ["role:" ++ slotName ix "roles" v]
        CIn "zone" vs -> ["zone:" ++ slotName ix "zone" v | v <- vs]
        _ -> [] | a <- atomsOf c ]

validationPointsJ :: Ix -> J
validationPointsJ ix = arr
  [ obj [ ("flow", str (fName f)), ("node", str (fTo f)), ("zone", str (zName zb)), ("kind", str kind), ("status", str (if present then "present" else "proposed")), ("class", str (className ix r)) ]
  | c <- crossings ix, let f = crFlow c, let zb = crToZ c, let r = crRank c
  , (kind, ctl) <- [("authorization", "authorization"), ("input_validation", "input_validation"), ("schema_validation", "schema_validation"), ("integrity_check", "integrity_check")]
  , ctl `elem` crReq c, let present = ctl `elem` crProv c ] `plus`
  arr [ obj [ ("flow", str (fName f)), ("node", str (fTo f)), ("zone", str (zName (crToZ c))), ("kind", str "boundary_assertion"), ("status", str "proposed"), ("class", str (className ix (crRank c))) ]
      | c <- crossings ix, let f = crFlow c ]
  `plus` arr [ obj [ ("flow", str (fName (crFlow c))), ("node", str (fTo (crFlow c))), ("zone", str (zName (crToZ c))), ("kind", str "data_classification"), ("status", str "proposed"), ("class", str (className ix (crRank c))) ]
      | c <- crossings ix, crRank c >= 2 ]
  where plus (JArr a) (JArr b) = JArr (a ++ b)
        plus a _ = a

guardsJ :: Ix -> J
guardsJ ix = arr
  [ obj [ ("node", str (nName n)), ("kind", str (kindName (nKind n))), ("zone", str (nZone n)), ("guard", str g)
        , ("enforces", strs [fName f | f <- moFlows m, fTo f == nName n || fFrom f == nName n])
        , ("effects", strs ["allow", "deny", "require_mfa", "require_approval", "redact", "encrypt", "audit", "rate_limit", "tokenize", "quarantine", "require_trusted_zone"]) ]
  | n <- moNodes m, Just g <- [guardFor (nKind n)] ] `plusW`
  arr [ obj [("node", str (pdName w)), ("kind", str "workflow"), ("zone", str ""), ("guard", str "workflow_step_guard"), ("enforces", strs (propNames "steps" (pdProps w))), ("effects", strs ["allow", "deny", "require_approval", "audit"])] | w <- moWorkflows m ]
  where
    m = ixModel ix
    guardFor k = case k of
      KApi -> Just "http_middleware"; KService -> Just "grpc_interceptor"; KAgent -> Just "service_wrapper"; KQueue -> Just "queue_guard"
      KFileStore -> Just "storage_guard"; KCloud -> Just "storage_guard"; KDatabase -> Just "data_access_guard"; KExternal -> Just "egress_guard"
      KApplication -> Just "service_wrapper"; _ -> Nothing
    plusW (JArr a) (JArr b) = JArr (a ++ b)
    plusW a _ = a

graphJ :: Ix -> J
graphJ ix = obj
  [ ("nodes", arr [ obj [ ("id", str (nName n)), ("kind", str (kindName (nKind n))), ("zone", str (nZone n)), ("controls", strs (propNames "controls" (nProps n))), ("clearance", jmaybe str (propText "clearance" (nProps n))), ("line", jint (pLine (nPos n))) ] | n <- moNodes m ])
  , ("zones", arr [ obj [ ("id", str (zName z)), ("trust", jint (zTrust z)), ("kind", str (zKindS z)), ("maxClass", jmaybe str (zMax z)), ("line", jint (pLine (zPos z))) ] | z <- moZones m ])
  , ("edges", arr [ obj [ ("id", str (fName f)), ("from", str (fFrom f)), ("to", str (fTo f)), ("data", strs (fData f)), ("op", str (fOp f)), ("channel", str (fromMaybe "unspecified" (propText "channel" (fProps f))))
                        , ("controls", strs (providedControls ix f))
                        , ("crossing", jbool (fmap zName (nodeZone ix (fFrom f)) /= fmap zName (nodeZone ix (fTo f))))
                        , ("missing", strs (nub (concat [crMissing c | c <- cs, fName (crFlow c) == fName f])))
                        , ("maxClass", str (className ix (maximum (0 : [crRank c | c <- cs, fName (crFlow c) == fName f])))), ("line", jint (pLine (fPos f))) ]
                  | f <- moFlows m ]) ]
  where m = ixModel ix
        cs = crossings ix

metricsJ :: Ix -> [Finding] -> J
metricsJ ix fs = obj
  [ ("nodes", jint (length (moNodes m))), ("flows", jint (length (moFlows m))), ("zones", jint (length (moZones m))), ("dataTypes", jint (length (moData m)))
  , ("policies", jint (length (moPolicies m))), ("rules", jint (sum (map (length . plRules) (moPolicies m))))
  , ("boundaryCrossings", jint (length (nub [fName (crFlow c) | c <- cs, zName (crFromZ c) /= zName (crToZ c)])))
  , ("guardedNodes", jint (length [() | n <- moNodes m, not (null (propNames "controls" (nProps n)))]))
  , ("cyclomatic", jint (max 0 (length (moFlows m) - length (moNodes m) + 2)))
  , ("findingsBySeverity", obj [(levelName l, jint (length [() | f <- fs, fnLevel f == l])) | l <- reverse [minBound .. maxBound]]) ]
  where m = ixModel ix
        cs = crossings ix

-- | Model-simplification proposals (never applied automatically).
simplifierJ :: Ix -> J
simplifierJ ix = arr $
  [ obj [("kind", str "MergeNodes"), ("items", strs [nName a, nName b]), ("message", str ("nodes " ++ nName a ++ " and " ++ nName b ++ " have the same kind, zone, controls and identical neighbours; consider merging them"))]
  | (i, a) <- zip [0 :: Int ..] (moNodes m), (j, b) <- zip [0 ..] (moNodes m), i < j, nKind a == nKind b, nZone a == nZone b
  , nProps a == nProps b, sig (nName a) == sig (nName b), not (null (sig (nName a))) ] ++
  [ obj [("kind", str "MergeFlows"), ("items", strs [fName a, fName b]), ("message", str ("flows " ++ fName a ++ " and " ++ fName b ++ " connect the same nodes with the same operation; carry both data types in one flow"))]
  | (i, a) <- zip [0 :: Int ..] (moFlows m), (j, b) <- zip [0 ..] (moFlows m), i < j, fFrom a == fFrom b, fTo a == fTo b, fOp a == fOp b, fProps a == fProps b ]
  where
    m = ixModel ix
    sig n = sort ([(fTo f, fOp f, fData f) | f <- moFlows m, fFrom f == n] ++ [(fFrom f, fOp f, fData f) | f <- moFlows m, fTo f == n])
