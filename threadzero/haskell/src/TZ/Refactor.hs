-- | Security refactoring engine: graph transformations with preconditions,
--   postconditions, security/functional impact, cost estimate and residual risk.
--   Candidates are produced as new models (never applied to production).
module TZ.Refactor (refactorJ, analyzeQuick, scorecardJ) where

import Data.List (find, foldl', intercalate, nub, (\\))
import qualified Data.Map.Strict as M
import Data.Maybe (catMaybes, fromMaybe, listToMaybe)
import qualified Data.Set as S
import TZ.Analyzer
import TZ.Expr
import TZ.Json
import TZ.Policy
import TZ.Pretty
import TZ.Semantic
import TZ.Types

-- | Errors + findings for a model (used to validate candidates).
analyzeQuick :: Model -> ([Diag], [Finding])
analyzeQuick m = (errs, fs)
  where
    ix = mkIx m
    (rules, rd) = buildRules ix
    dom = policyDom ix rules
    fs = findings ix rules (conflicts ix dom rules)
    errs = [d | d <- checkModel ix ++ rd ++ policyDiags ix dom rules ++ fst (classPropagation ix), dSev d == SevError]

data Cand = Cand
  { cId :: String, cTitle :: String, cDesc :: String, cPre :: [(String, Bool)]
  , cOps :: [String], cNewNodes :: [String], cModel :: Model, cRulesAdded :: Int }

pr :: [(String, Value)] -> Props
pr ps = [Prop k noPos v | (k, v) <- ps]

ctlV :: [String] -> Value
ctlV = VList . map VId

freshNames :: Model -> [String] -> [String]
freshNames m = go []
  where
    taken = map nName (moNodes m)
    go acc [] = reverse acc
    go acc (b : bs) = let n = head [c | i <- [0 :: Int ..], let c = if i == 0 then b else b ++ show i, c `notElem` taken, c `notElem` acc] in go (n : acc) bs

addNodes :: [NodeR] -> Model -> Model
addNodes ns m = renumber m { moNodes = moNodes m ++ ns }

replaceFlow :: String -> [FlowR] -> Model -> Model
replaceFlow n new m = m { moFlows = concat [if fName f == n then new else [f] | f <- moFlows m] }

flowKeep :: FlowR -> Props
flowKeep f = [p | p <- fProps f, prKey p `notElem` ["controls", "channel"]]

mkFlow :: FlowR -> String -> String -> String -> [String] -> String -> [String] -> String -> FlowR
mkFlow f suffix a b ds op ctl chan =
  f { fName = fName f ++ "__" ++ suffix, fFrom = a, fTo = b, fData = ds, fOp = op
    , fProps = flowKeep f ++ pr [("controls", ctlV ctl), ("channel", VId chan)] }

ensureZone :: Model -> String -> String -> Int -> (Model, String)
ensureZone m kind name trust = case [zName z | z <- moZones m, zKindS z == kind] of
  (z : _) -> (m, z)
  [] -> (renumber m { moZones = moZones m ++ [ZoneR noPos name 0 trust kind Nothing []] }, name)

candidatesFor :: Model -> Finding -> [Cand]
candidatesFor m f = catMaybes $ case fnCat f of
  c | c `elem` ["MissingAuthentication", "MissingAuthorization", "UnvalidatedInputPath", "SecurityControlGap"] -> [gateway False, gateway True, harden]
    | c == "MissingAudit" -> [harden, gateway False]
    | c `elem` ["TrustBoundaryViolation", "SensitiveDataEscape"] -> [tokenize "Tokenizer" "Token" "tokenization", tokenize "Redactor" "Redacted" "redaction", guardrails]
    | c == "UncontrolledThirdPartyFlow" -> [gateway False, approval, tokenize "Redactor" "Redacted" "redaction"]
    | c == "SecretExposurePath" -> [guardrails, tokenize "Redactor" "Redacted" "redaction"]
    | c == "DirectDatabaseAccess" -> [repository, gateway False]
    | c == "ExcessivePrivilege" -> [splitNode, guardrails]
    | c == "UnsafeDataFanOut" -> [broker]
    | otherwise -> []
  where
    ix = mkIx m
    eff = effClassOf ix
    flow = fnFlow f >>= \n -> find ((== n) . fName) (moFlows m)
    cross fl = [c | c <- crossings ix, fName (crFlow c) == fName fl]

    gateway chain = do
      fl <- flow
      za <- nodeZone ix (fFrom fl)
      zb <- nodeZone ix (fTo fl)
      let egress = zTrust za > zTrust zb
          zone = if egress || zTrust za == zTrust zb then zName za else zName zb
          reqAll = nub (concatMap crReq (cross fl))
          ctl = nub (filter (/= "approval") (reqAll ++ ["authentication", "authorization", "audit"]))
          stages | not chain = [("Gateway", ctl)]
                 | egress = [("PolicyEnforcement", ["authorization", "audit"]), ("Filter", ["output_filtering", "redaction", "data_minimization"]), ("EgressGateway", ctl)]
                 | otherwise = [("Gateway", ctl), ("PolicyEnforcement", ["authorization", "audit"]), ("Sanitizer", ["schema_validation", "input_validation", "integrity_check"])]
          names = freshNames m [s ++ "_" ++ fName fl | (s, _) <- stages]
          lastIx = length stages - 1
          nodes = [ NodeR noPos KService nm 0 zone (pr [(if egress && i == lastIx then "egress_controls" else "controls", ctlV c)])
                  | (i, (nm, (_, c))) <- zip [0 :: Int ..] (zip names stages) ]
          hops = zip (fFrom fl : names) (names ++ [fTo fl])
          flows' = [ mkFlow fl ("hop" ++ show i) a b (fData fl) (fOp fl) [] (if i == 0 || i == length hops - 1 then "mtls" else "internal")
                   | (i, (a, b)) <- zip [0 :: Int ..] hops ]
      pure Cand
        { cId = if chain then "chain" else "gateway"
        , cTitle = if chain then "Gateway → Policy Enforcement → Sanitization chain" else "Compact enforcement gateway"
        , cDesc = "Route " ++ fName fl ++ " through " ++ (if chain then "a staged enforcement chain" else "a single enforcement gateway") ++ " in zone " ++ zone ++ "."
        , cPre = [("flow " ++ fName fl ++ " exists", True), ("both endpoints belong to known zones", True)]
        , cOps = ["remove flow " ++ fName fl] ++ ["add service " ++ n ++ " in " ++ zone | n <- names] ++ ["add flows " ++ intercalate " -> " (fFrom fl : names ++ [fTo fl])]
        , cNewNodes = names, cModel = replaceFlow (fName fl) flows' (addNodes nodes m), cRulesAdded = 0 }

    harden = do
      fl <- flow
      let reqAll = nub (concatMap crReq (cross fl))
          ctl = nub (propNames "controls" (fProps fl) ++ fnMissing f ++ reqAll)
          d = case fData fl of (x : _) -> x; [] -> ""
          polName = "Enforce_" ++ fName fl
          rule = Rule noPos "RequireSecureChannel" EfDeny
                   (Just (XAnd (XCmp noPos OpEq (XAttr noPos "data") (XId noPos d)) (XNot (XAttr noPos "context.secure_channel"))))
                   (Just ("flow " ++ fName fl ++ " requires a secure channel")) [EfAudit] Nothing
          pol = PolicyDef noPos polName "1.0.0" 800 (ScResource (fTo fl)) Nothing [rule]
          fl' = fl { fProps = flowKeep fl ++ pr [("controls", ctlV ctl), ("channel", VId "mtls")] }
          addPol = not (null d) && polName `notElem` map plName (moPolicies m)
          m' = m { moFlows = [if fName x == fName fl then fl' else x | x <- moFlows m], moPolicies = moPolicies m ++ [pol | addPol] }
      pure $ Cand "harden" "Harden the flow in place (policy layer)"
        ("Add the missing controls to " ++ fName fl ++ ", switch it to mTLS and add a deny policy for non-secure channels.")
        [("flow " ++ fName fl ++ " exists", True)]
        (["set controls of " ++ fName fl ++ " to " ++ unwords ctl, "set channel mtls"] ++ ["add policy " ++ polName | addPol]) [] m' (if addPol then 1 else 0)

    tokenize prefix suffix ctlName = do
      fl <- flow
      let sensitive = [d | d <- fData fl, M.findWithDefault 0 d eff >= 2]
      d <- listToMaybe (sensitive ++ fData fl)
      let (m1, zsec) = ensureZone m "SecureProcessingZone" "SecureProcessing" 4
          [nm] = freshNames m1 [prefix ++ "_" ++ fName fl]
          tokName = head [n | i <- [0 :: Int ..], let n = d ++ suffix ++ (if i == 0 then "" else show i), n `notElem` map dtName (moData m1)]
          destTrust = maybe 0 zTrust (nodeZone ix (fTo fl))
          tokClass = if destTrust <= 0 then "Public" else "Internal"
          approvals = [nName n | n <- moNodes m1, nKind n == KApproval]
          declProps = pr ([("data", VId d), ("produces", VId tokName), ("via", VId nm)] ++ [("approval", VId (head approvals)) | not (null approvals)])
          tokNode = NodeR noPos KService nm 0 zsec (pr [("controls", ctlV ["authentication", "authorization", "audit", ctlName, "isolation"]), ("clearance", VId (className ix (dataRank ix d)))])
          m2 = addNodes [tokNode] m1
          widen dr | dtName dr == d && not (null (propNames "zones" (dtProps dr))) =
                       dr { dtProps = [p | p <- dtProps dr, prKey p /= "zones"] ++ pr [("zones", VList (map VId (nub (propNames "zones" (dtProps dr) ++ [zsec]))))] }
                   | otherwise = dr
          newData = DataR noPos tokName 0 tokClass (pr [("derived_from", VList [VId d]), ("description", VStr ("derivative of " ++ d ++ " produced by " ++ nm))])
          m3 = m2 { moData = map widen (moData m2) ++ [newData], moDeclass = moDeclass m2 ++ [PropDecl noPos ("Declassify_" ++ tokName) declProps] }
          f1 = mkFlow fl "in" (fFrom fl) nm (fData fl) "Transform" ["audit"] "mtls"
          f2 = mkFlow fl "out" nm (fTo fl) [if x == d then tokName else x | x <- fData fl] (fOp fl) [] "mtls"
          m4 = renumber (replaceFlow (fName fl) [f1, f2] m3)
          tok = ctlName == "tokenization"
      pure $ Cand (if tok then "tokenize" else "redact") (if tok then "Tokenization layer in a secure zone" else "Redaction in a secure processing zone")
        ("Keep " ++ d ++ " inside " ++ zsec ++ " and send only the derived data " ++ tokName ++ " (" ++ tokClass ++ ") across the boundary.")
        [("flow " ++ fName fl ++ " carries sensitive data", not (null sensitive)), ("a secure processing zone exists or can be created", True)]
        (["add service " ++ nm ++ " in " ++ zsec, "add data " ++ tokName ++ " derived from " ++ d, "add declassify Declassify_" ++ tokName, "replace flow " ++ fName fl ++ " with " ++ fName fl ++ "__in / " ++ fName fl ++ "__out"])
        [nm] m4 0

    guardrails = do
      let pol = PolicyDef noPos "ThreadZeroGuardrails" "1.0.0" 900 ScGlobal Nothing
                  [ Rule noPos "RestrictedOnlyInTrustedZones" EfDeny
                      (Just (XAnd (XCmp noPos OpGe (XAttr noPos "data.classification") (XNum 3)) (XCmp noPos OpLt (XAttr noPos "zone.trust") (XNum 3))))
                      (Just "Restricted data may only be processed in trusted zones") [EfAudit] Nothing
                  , Rule noPos "SecretsNeverLogged" EfDeny
                      (Just (XAnd (XCmp noPos OpEq (XAttr noPos "action") (XId noPos "Log")) (XCmp noPos OpGe (XAttr noPos "data.classification") (XNum 5))))
                      (Just "Secrets must never be logged") [EfAudit] Nothing ]
          exists = "ThreadZeroGuardrails" `elem` map plName (moPolicies m)
      if exists then Nothing else
        pure $ Cand "guardrails" "Runtime guardrail policy"
          "Add a high-priority policy that denies Restricted data outside trusted zones and forbids logging secrets. No structural change; enforced by the WASM guard."
          [("policy ThreadZeroGuardrails does not exist", True)] ["add policy ThreadZeroGuardrails (priority 900)"] [] m { moPolicies = moPolicies m ++ [pol] } 2

    approval = do
      fl <- flow
      let zadm = case [zName z | z <- moZones m, zKindS z == "AdminZone"] of
            (z : _) -> z
            [] -> maybe "" zName (nodeZone ix (fFrom fl))
          [nm] = freshNames m ["Approval_" ++ fName fl]
          d = case fData fl of (x : _) -> x; [] -> ""
          fl' = fl { fProps = [p | p <- fProps fl, prKey p /= "controls"] ++ pr [("controls", ctlV (nub (propNames "controls" (fProps fl) ++ ["approval", "audit"])))] }
          pol = PolicyDef noPos ("Approve_" ++ fName fl) "1.0.0" 700 (ScResource (fTo fl)) Nothing
                  [Rule noPos "RequireHumanApproval" EfRequireApproval (Just (XCmp noPos OpEq (XAttr noPos "data") (XId noPos d))) (Just "human approval required") [EfAudit] Nothing]
          wf = PropDecl noPos ("Approved_" ++ fName fl) (pr [("steps", VList [VId (fName fl)]), ("approvals", VList [VId nm])])
          m1 = addNodes [NodeR noPos KApproval nm 0 zadm (pr [("description", VStr ("human approval point for " ++ fName fl))])] m
          m2 = m1 { moFlows = [if fName x == fName fl then fl' else x | x <- moFlows m1], moPolicies = moPolicies m1 ++ [pol | not (null d)], moWorkflows = moWorkflows m1 ++ [wf] }
      pure $ Cand "approval" "Human approval boundary"
        ("Require human approval for " ++ fName fl ++ " (approval node " ++ nm ++ ", RequireApproval obligation, workflow step).")
        [("flow exists", True)] ["add approval node " ++ nm, "add approval + audit controls to the flow", "add policy Approve_" ++ fName fl, "add workflow Approved_" ++ fName fl]
        [nm] m2 1

    repository = do
      fl <- flow
      let fromDb = (nKind <$> M.lookup (fFrom fl) (ixNode ix)) == Just KDatabase
          db = if fromDb then fFrom fl else fTo fl
          zone = maybe "" nZone (M.lookup db (ixNode ix))
          [nm] = freshNames m ["Repo_" ++ db]
          m1 = addNodes [NodeR noPos KService nm 0 zone (pr [("controls", ctlV ["authentication", "authorization", "input_validation", "schema_validation", "audit", "integrity_check", "encryption"]), ("egress_controls", ctlV ["output_filtering", "audit", "redaction", "data_minimization"])])] m
          (a1, b1, a2, b2) = if fromDb then (db, nm, nm, fTo fl) else (fFrom fl, nm, nm, db)
      pure $ Cand "repository" "Repository service in front of the database"
        ("Introduce " ++ nm ++ " so that no client talks to " ++ db ++ " directly.")
        [("flow touches a database", True)] ["add service " ++ nm ++ " in " ++ zone, "replace flow " ++ fName fl ++ " with a two-hop path through " ++ nm]
        [nm] (replaceFlow (fName fl) [mkFlow fl "in" a1 b1 (fData fl) (fOp fl) [] "mtls", mkFlow fl "out" a2 b2 (fData fl) (fOp fl) [] "mtls"] m1) 0

    splitNode = do
      fl <- flow
      n <- M.lookup (fTo fl) (ixNode ix)
      cl <- propText "clearance" (nProps n)
      let limit = M.findWithDefault 0 cl (ixClass ix)
          [hiName] = freshNames m [nName n ++ "_High"]
          hiRank = maximum (0 : [M.findWithDefault 0 d eff | x <- moFlows m, fTo x == nName n || fFrom x == nName n, d <- fData x])
          isHigh x = any (\d -> M.findWithDefault 0 d eff > limit) (fData x)
          re x = x { fFrom = if fFrom x == nName n && isHigh x then hiName else fFrom x, fTo = if fTo x == nName n && isHigh x then hiName else fTo x }
          hi = n { nName = hiName, nProps = [p | p <- nProps n, prKey p /= "clearance"] ++ pr [("clearance", VId (className ix hiRank))] }
          m1 = addNodes [hi] m
      pure $ Cand "split" "Split node by classification (least privilege)"
        ("Split " ++ nName n ++ " into a " ++ cl ++ "-cleared component and " ++ hiName ++ " for higher-classification data.")
        [("node has an explicit clearance", True)] ["add service " ++ hiName, "re-point flows carrying data above " ++ cl ++ " to " ++ hiName]
        [hiName] m1 { moFlows = map re (moFlows m1) } 0

    broker = do
      d <- fnData f
      n <- listToMaybe (fnAffected f)
      let outs = [x | x <- moFlows m, fFrom x == n, d `elem` fData x]
      first <- listToMaybe outs
      let zone = maybe "" nZone (M.lookup n (ixNode ix))
          [nm] = freshNames m ["Broker_" ++ n ++ "_" ++ d]
          m1 = addNodes [NodeR noPos KService nm 0 zone (pr [("controls", ctlV ["authorization", "audit", "data_minimization"]), ("egress_controls", ctlV ["data_minimization", "audit", "output_filtering"])])] m
          inF = first { fName = rootName (fName first) ++ "__in", fTo = nm, fOp = "Copy", fData = [d], fProps = pr [("controls", ctlV ["audit"]), ("channel", VId "mtls")] }
          outF = [o { fName = fName o ++ "__out", fFrom = nm, fProps = [p | p <- fProps o, prKey p /= "controls"] ++ pr [("controls", ctlV (nub (propNames "controls" (fProps o) ++ ["data_minimization", "audit"])))] } | o <- outs]
          names = map fName outs
      pure $ Cand "broker" "Policy-enforcing distribution broker"
        ("Replace " ++ show (length outs) ++ " direct fan-out flows of " ++ d ++ " from " ++ n ++ " with one flow into " ++ nm ++ " that minimizes per consumer.")
        [("fan-out exists", True)] ["add service " ++ nm, "replace " ++ show (length outs) ++ " flows by a single flow plus per-consumer flows"]
        [nm] m1 { moFlows = filter ((`notElem` names) . fName) (moFlows m1) ++ [inF] ++ outF } 0

-- ---------------------------------------------------------------------------

reach :: Model -> S.Set (String, String)
reach m = S.fromList [(a, b) | a <- ns, b <- go S.empty [a], b /= a]
  where
    ns = map nName (moNodes m)
    go seen [] = S.toList seen
    go seen (x : xs) = let nxt = [fTo f | f <- moFlows m, fFrom f == x, fTo f `S.notMember` seen] in go (foldr S.insert seen nxt) (xs ++ nxt)

scorecardJ :: Model -> [Finding] -> J
scorecardJ m fs = obj
  [ ("findings", jint (length fs)), ("boundaryCrossings", jint (length (nub [fName (crFlow c) | c <- cs, zName (crFromZ c) /= zName (crToZ c)])))
  , ("guards", jint (length [() | n <- moNodes m, not (null (propNames "controls" (nProps n)) && null (propNames "egress_controls" (nProps n)))]))
  , ("policyRules", jint (sum (map (length . plRules) (moPolicies m))))
  , ("policyComplexity", jint (sum [1 + maybe 0 exprSize (ruWhen r) | p <- moPolicies m, r <- plRules p]))
  , ("components", jint (length (moNodes m))), ("flows", jint (length (moFlows m)))
  , ("dataMovement", jint (length [() | c <- cs, crRank c >= 2]))
  , ("runtimeOverheadEstimateMs", jnum (0.4 * fromIntegral (length (moFlows m)) / 10 + 0.02 * fromIntegral (sum (map (length . plRules) (moPolicies m)))))
  , ("residualBySeverity", obj [(levelName l, jint (length [() | x <- fs, fnLevel x == l])) | l <- reverse [minBound .. maxBound]]) ]
  where
    ix = mkIx m
    cs = crossings ix
    exprSize e = case e of
      XAnd a b -> 1 + exprSize a + exprSize b
      XOr a b -> 1 + exprSize a + exprSize b
      XNot a -> 1 + exprSize a
      _ -> 1

refactorJ :: Model -> String -> J
refactorJ m fid = case [(i, f) | (i, f) <- zip [0 :: Int ..] baseFs, "F-" ++ pad3 (i + 1) == fid] of
  [] -> obj [("error", str ("unknown finding " ++ fid)), ("candidates", arr [])]
  ((_, f) : _) ->
    let cands = candidatesFor m f
    in obj [ ("finding", findingJ 0 f), ("fingerprint", str (fingerprint f))
           , ("base", obj [("dsl", str (prettyModel m)), ("scorecard", scorecardJ m baseFs)])
           , ("candidates", arr (zipWith (candJ f) ['A' ..] cands)) ]
  where
    (_, baseFs0) = analyzeQuick m
    baseFs = baseFs0
    basePairs = reach m
    baseFps = map fingerprint baseFs
    pad3 n = let s = show n in replicate (3 - length s) '0' ++ s
    candJ f letter c =
      let (errs, fs') = analyzeQuick (cModel c)
          newFps = map fingerprint fs'
          removed = baseFps \\ newFps
          added = newFps \\ baseFps
          origNodes = S.fromList (map nName (moNodes m))
          newPairs = S.filter (\(a, b) -> a `S.member` origNodes && b `S.member` origNodes) (reach (cModel c))
          lost = S.toList (basePairs `S.difference` newPairs)
          targetGone = fingerprint f `notElem` newFps
          noNewSevere = null [x | x <- fs', fingerprint x `elem` added, fnLevel x >= LHigh]
          residual = [x | x <- fs', fingerprint x `elem` (baseFps `intersect'` newFps)]
          intersect' a b = [x | x <- a, x `elem` b]
          hops = length (moFlows (cModel c)) - length (moFlows m)
      in obj
        [ ("id", str [letter]), ("kind", str (cId c)), ("title", str (cTitle c)), ("description", str (cDesc c))
        , ("valid", jbool (null errs)), ("errors", strs [dMsg d | d <- errs])
        , ("preconditions", arr [obj [("text", str t), ("holds", jbool h)] | (t, h) <- cPre c])
        , ("transformation", strs (cOps c))
        , ("postconditions", arr [ obj [("text", str "the selected finding is removed"), ("holds", jbool targetGone)]
                                 , obj [("text", str "no new High or Critical findings are introduced"), ("holds", jbool noNewSevere)]
                                 , obj [("text", str "every original node pair that was connected stays connected"), ("holds", jbool (null lost))]
                                 , obj [("text", str "the candidate model has no semantic errors"), ("holds", jbool (null errs))] ])
        , ("securityImpact", obj [("removed", strs removed), ("added", strs added), ("remaining", jint (length fs'))])
        , ("functionalImpact", obj [("equivalent", jbool (null lost)), ("lostPairs", arr [strs [a, b] | (a, b) <- take 10 lost]), ("addedHops", jint hops)])
        , ("cost", obj [("newComponents", jint (length (cNewNodes c))), ("rulesAdded", jint (cRulesAdded c)), ("latencyEstimateMs", jnum (0.4 * fromIntegral (max 0 hops)))])
        , ("newComponents", strs (cNewNodes c))
        , ("residualRisk", arr [obj [("fingerprint", str (fingerprint x)), ("severity", str (levelName (fnLevel x))), ("category", str (fnCat x))] | x <- take 12 residual])
        , ("scorecard", scorecardJ (cModel c) fs')
        , ("dsl", str (prettyModel (cModel c))) ]
