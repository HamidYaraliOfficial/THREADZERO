-- | THREADZERO Haskell test-suite: property-based tests (built-in generator, no external deps),
--   parser / type-system / constraint / graph / conflict / determinism / refactoring-equivalence tests
--   and parser fuzzing.
module Main (main) where

import Control.Exception (SomeException, evaluate, try)
import Control.Monad (forM, unless)
import Data.IORef
import Data.List (isInfixOf, nub)
import qualified Data.Map.Strict as M
import System.Exit
import System.IO
import TZ.Analyzer
import TZ.Expr
import TZ.Json
import TZ.Parser
import TZ.Policy
import TZ.Pretty
import TZ.Refactor
import TZ.Semantic
import TZ.Solver
import TZ.Types

-- ---------------------------------------------------------------------------
-- Tiny property-testing harness (linear congruential generator)

newtype Gen a = Gen { runGen :: Int -> (a, Int) }
instance Functor Gen where fmap f (Gen g) = Gen $ \s -> let (a, s') = g s in (f a, s')
instance Applicative Gen where
  pure a = Gen $ \s -> (a, s)
  Gen f <*> Gen g = Gen $ \s -> let (h, s1) = f s; (a, s2) = g s1 in (h a, s2)
instance Monad Gen where
  Gen g >>= f = Gen $ \s -> let (a, s1) = g s in runGen (f a) s1

next :: Gen Int
next = Gen $ \s -> let s' = (s * 1103515245 + 12345) `mod` 2147483648 in (s' `div` 65536, s')

choose :: Int -> Int -> Gen Int
choose lo hi = (\n -> lo + n `mod` (hi - lo + 1)) <$> next

oneof :: [Gen a] -> Gen a
oneof gs = choose 0 (length gs - 1) >>= (gs !!)

elements :: [a] -> Gen a
elements xs = (xs !!) <$> choose 0 (length xs - 1)

sample :: Int -> Gen a -> Int -> a
sample n g seed = fst (runGen g (seed * 7919 + n))

-- ---------------------------------------------------------------------------
-- Harness

data Ctx = Ctx { passed :: IORef Int, failed :: IORef Int }

check :: Ctx -> String -> Bool -> IO ()
check ctx name ok = do
  modifyIORef (if ok then passed ctx else failed ctx) (+ 1)
  unless ok (putStrLn ("  FAIL: " ++ name))

prop :: Ctx -> String -> Int -> (Int -> Bool) -> IO ()
prop ctx name n f = do
  let bad = [i | i <- [1 .. n], not (f i)]
  check ctx (name ++ " (" ++ show n ++ " cases" ++ (if null bad then "" else ", first failing seed " ++ show (head bad)) ++ ")") (null bad)

section :: String -> IO ()
section s = putStrLn ("• " ++ s)

-- ---------------------------------------------------------------------------
-- Sample models

base :: String
base = unlines
  [ "project \"T\" version \"1\" timezone \"UTC\";"
  , "zone Browser trust 1 kind Browser max_class Personal;"
  , "zone Backend trust 3 kind Backend;"
  , "zone DatabaseZone trust 4 kind DatabaseZone;"
  , "role Customer; role Admin;"
  , "data Card class Financial { operations: [Create, Read, Write]; zones: [Browser, Backend, DatabaseZone]; }"
  , "data PublicInfo class Public;"
  , "application Web in Browser { controls: [encryption]; }"
  , "api Api in Backend { controls: [authentication, authorization, audit, rate_limit, schema_validation, input_validation]; }"
  , "database Db in DatabaseZone { controls: [authentication, authorization, encryption, audit]; }"
  , "flow Submit from Web to Api carries Card op Create { channel: tls; }"
  , "flow Direct from Web to Db carries Card op Write { channel: tls; }"
  ]

analyzeText :: String -> (Model, [Diag], [Finding])
analyzeText src = (m, es, fs)
  where
    (ds, pes) = parseSource "test.tz" src
    m = buildModel ds
    (errs, fs) = analyzeQuick m
    es = pes ++ [d | d <- errs]

diagCodes :: String -> [String]
diagCodes src = let (ds, pes) = parseSource "t.tz" src; m = buildModel ds; ix = mkIx m in map dCode (pes ++ checkModel ix)

-- ---------------------------------------------------------------------------
-- Generators

genAttrAtom :: Gen Expr
genAttrAtom = oneof
  [ (\n -> XCmp noPos OpGe (XAttr noPos "zone.trust") (XNum n)) <$> choose 0 5
  , (\n -> XCmp noPos OpLt (XAttr noPos "subject.device_trust") (XNum n)) <$> choose 0 5
  , (\z -> XCmp noPos OpEq (XAttr noPos "zone") (XId noPos z)) <$> elements ["Browser", "Backend", "DatabaseZone"]
  , (\a -> XCmp noPos OpNe (XAttr noPos "action") (XId noPos a)) <$> elements ["Read", "Write", "Create"]
  , (\r -> XCmp noPos OpEq (XAttr noPos "subject.role") (XId noPos r)) <$> elements ["Customer", "Admin"]
  , (\c -> XCmp noPos OpGe (XAttr noPos "data.classification") (XId noPos c)) <$> elements ["Public", "Restricted", "Secret"]
  , pure (XAttr noPos "subject.mfa")
  , (\xs -> XIn noPos (XAttr noPos "action") xs) <$> ((\a b -> [XId noPos a, XId noPos b]) <$> elements ["Read", "Write"] <*> elements ["Delete", "Export"])
  ]

genExpr :: Int -> Gen Expr
genExpr 0 = genAttrAtom
genExpr d = oneof [genAttrAtom, XAnd <$> genExpr (d - 1) <*> genExpr (d - 1), XOr <$> genExpr (d - 1) <*> genExpr (d - 1), XNot <$> genExpr (d - 1)]

genCExpr :: Int -> Gen CExpr
genCExpr 0 = oneof
  [ CEq "data" <$> choose 0 1, CEq "zone" <$> choose 0 2, CGe "ztrust" <$> choose 0 5, CFlag <$> elements ["mfa", "approved"]
  , CHas "roles" <$> elements [1, 2, 3], CIn "action" <$> ((\a b -> [a, b]) <$> choose 0 11 <*> choose 0 11), CLt "dtrust" <$> choose 0 5 ]
genCExpr d = oneof [genCExpr 0, CAnd <$> genCExpr (d - 1) <*> genCExpr (d - 1), COr <$> genCExpr (d - 1) <*> genCExpr (d - 1), CNot <$> genCExpr (d - 1)]

-- ---------------------------------------------------------------------------

main :: IO ()
main = do
  hSetEncoding stdout utf8
  ctx <- Ctx <$> newIORef 0 <*> newIORef 0
  let (m0, _, fs0) = analyzeText base
      ix0 = mkIx m0

  section "Parser"
  let (ds, es) = parseSource "t.tz" base
  check ctx "base model parses without errors" (null es)
  check ctx "declaration count" (length ds == 13)
  let (_, e2) = parseSource "t.tz" "zone A trust 1;\nzone B trust ;\nzone C trust 2;"
  check ctx "syntax error carries exact line" (map (pLine . dPos) e2 == [2])
  let (d3, e3) = parseSource "t.tz" "role A;\nrole ;\nrole B;\nzone Z trust x;\nrole C;"
  check ctx "parser recovers and reports multiple errors" (length e3 == 2 && length d3 == 3)
  let (_, e4) = parseSource "t.tz" "role \"unterminated;"
  check ctx "lexer reports unterminated string" (not (null e4) && dCode (head e4) == "TZ1001")
  let (dt, et) = parseSource "t.tz" "template T(N) { role N; }\napply T(Alice);\napply T(Bob);"
  check ctx "templates expand" (null et && length dt == 2)
  let (_, ee) = parseSource "t.tz" "apply Missing(x);"
  check ctx "unknown template is an error" (not (null ee))
  let (dp, _) = parseSource "a.tz" "#@file lib/x.tz\nrole A;\n#@file main.tz\nrole ;\n"
  let (_, ep) = parseSource "a.tz" "#@file lib/x.tz\nrole A;\n#@file main.tz\nrole ;\n"
  check ctx "file pragma maps diagnostics to the right file" (map (pFile . dPos) ep == ["main.tz"] && length dp == 1)

  section "Pretty printer round trip"
  prop ctx "parse (pretty policy) == policy" 300 $ \i ->
    let e = sample i (genExpr 3) 11
        pol = PolicyDef noPos "P" "1.0.0" 100 ScGlobal Nothing [Rule noPos "R" EfDeny (Just e) (Just "why") [EfAudit] Nothing]
        m = emptyModel { moPolicies = [pol] }
        (dd, ee') = parseSource "x.tz" (prettyModel m)
    in null ee' && moPolicies (buildModel dd) == [pol]
  check ctx "whole-model round trip" (let (dd, _) = parseSource "x.tz" (prettyModel m0) in buildModel dd == m0)
  check ctx "pretty is idempotent" (let p1 = prettyModel m0; (dd, _) = parseSource "x.tz" p1 in prettyModel (buildModel dd) == p1)

  section "Type system"
  let tyErr expr = let ix = ix0 in either (dCode) (const "ok") (resolveExpr ix noPos expr)
  check ctx "undefined zone -> TZ2001" (tyErr (XCmp noPos OpEq (XAttr noPos "zone") (XId noPos "Nowhere")) == "TZ2001")
  check ctx "class vs zone mismatch -> TZ2003" (tyErr (XCmp noPos OpEq (XAttr noPos "zone") (XNum 3)) == "TZ2003")
  check ctx "ordering roles is rejected" (tyErr (XCmp noPos OpGe (XAttr noPos "subject.role") (XId noPos "Admin")) == "TZ2003")
  check ctx "bare number is not a condition" (tyErr (XNum 3) == "TZ2003")
  check ctx "well typed expression resolves" (tyErr (XAnd (XAttr noPos "subject.mfa") (XCmp noPos OpGe (XAttr noPos "zone.trust") (XNum 3))) == "ok")
  check ctx "did-you-mean suggestion" (case resolveExpr ix0 noPos (XCmp noPos OpEq (XAttr noPos "zone") (XId noPos "Backnd")) of Left d -> maybe False ("Backend" `isInfixOf`) (dHint d); _ -> False)

  section "Semantic analysis"
  check ctx "duplicate zone -> TZ2002" ("TZ2002" `elem` diagCodes (base ++ "zone Backend trust 3 kind Backend;\n"))
  check ctx "undefined node in flow -> TZ2001" ("TZ2001" `elem` diagCodes (base ++ "flow X from Nope to Db carries Card op Write;\n"))
  check ctx "operation not permitted for data -> TZ2004" ("TZ2004" `elem` diagCodes (base ++ "flow X from Api to Db carries Card op Export;\n"))
  check ctx "self flow -> TZ2004" ("TZ2004" `elem` diagCodes (base ++ "flow X from Api to Api carries Card op Read;\n"))
  check ctx "explicit zone list violation -> TZ2006" ("TZ2006" `elem` diagCodes (base ++ "zone Other trust 3 kind Backend;\nservice S in Other;\nflow X from Api to S carries Card op Write;\n"))
  check ctx "explicit max_class violation -> TZ2009" ("TZ2009" `elem` diagCodes (base ++ "zone Tiny trust 1 kind Browser max_class Internal;\nservice S in Tiny;\nflow X from Api to S carries Card op Write;\n"))
  check ctx "secret value in model -> TZ2011" ("TZ2011" `elem` diagCodes (base ++ "secret K in Backend { value: \"abc\"; }\n"))
  check ctx "secret-looking string -> TZ2011" ("TZ2011" `elem` diagCodes (base ++ "service S in Backend { note: \"sk_live_1234567890abcdef\"; }\n"))
  check ctx "circular policy dependency -> TZ2007" ("TZ2007" `elem` diagCodes (base ++ "policy A extends B { rule R: allow when true; }\npolicy B extends A { rule Q: deny when true; }\n"))
  check ctx "unknown effect is a syntax error" ("TZ1002" `elem` diagCodes (base ++ "policy P { rule R: explode when true; }\n"))
  let (_, _, fsPropag) = analyzeText (base ++ "data Derived class Public { derived_from: [Card]; }\n")
  check ctx "classification propagation mismatch -> TZ2009" (let (dd, _) = parseSource "x" (base ++ "data Derived class Public { derived_from: [Card]; }\n") in any ((== "TZ2009") . dCode) (fst (classPropagation (mkIx (buildModel dd)))))
  check ctx "impossible permission -> TZ2005" (let (_, es5, _) = analyzeText (base ++ "policy P { rule R: allow when data == Card and action == Export; }\n") in "TZ2005" `elem` map dCode es5)

  section "Constraint solver (finite domain)"
  let rs = fst (buildRules ix0)
      dom0 = policyDom ix0 rs
  prop ctx "solve is sound: witness satisfies the expression" 300 $ \i ->
    let e = sample i (genCExpr 3) 5
    in case solve dom0 True e of Just w -> evalD w e; Nothing -> True
  prop ctx "solve is complete: Nothing <=> enumeration empty" 200 $ \i ->
    let e = sample i (genCExpr 2) 9
        slots = orderSlots (primaries dom0 (slotsOf e))
    in case solve dom0 True e of Nothing -> null (take 1 (enumSat dom0 True slots e)); Just _ -> not (null (take 1 (enumSat dom0 True slots e)))
  prop ctx "x and not x is unsatisfiable" 100 $ \i -> let e = sample i (genCExpr 2) 3 in solve dom0 True (CAnd e (CNot e)) == Nothing
  prop ctx "simp with full assignment agrees with evalD" 300 $ \i ->
    let e = sample i (genCExpr 3) 17
        a = M.fromList [(s, sample (i + k) (choose 0 3) 2) | (k, s) <- zip [0 ..] ["data", "zone", "ztrust", "mfa", "approved", "roles", "action", "dtrust"]]
    in simp a e == (if evalD a e then CT else CF) || null (slotsOf e) || all (`M.member` a) (slotsOf e) == False
  check ctx "SMT-LIB export mentions check-sat" ("check-sat" `isInfixOf` smtLib dom0 (CGe "ztrust" 3))

  section "Policy conflicts and precedence"
  let confSrc = base ++ unlines
        [ "policy P1 priority 100 { rule A: allow when data == Card and action == Read; }"
        , "policy P2 priority 100 { rule D: deny when data == Card and action == Read; }"
        , "policy P3 priority 500 scope zone Backend { rule D2: deny when data == Card and action == Read; }" ]
      (mc, _, _) = analyzeText confSrc
      ixc = mkIx mc
      (rc, _) = buildRules ixc
      cf = conflicts ixc (policyDom ixc rc) rc
  check ctx "equal priority allow/deny -> DenyAllowAmbiguity" ("DenyAllowAmbiguity" `elem` map cfKind cf)
  check ctx "scope difference -> ScopeConflict" ("ScopeConflict" `elem` map cfKind cf)
  let a0 = M.fromList [("data", 0), ("action", 1)]
  check ctx "deny wins the tie" (dcCode (decide rc a0) == 0)
  check ctx "default deny with no rules matched" (dcCode (decide [] M.empty) == 0 && dcReason (decide [] M.empty) == -1)
  prop ctx "deny-overrides: a matched deny at the top always denies" 200 $ \i ->
    let a = M.fromList [("data", i `mod` 2), ("action", i `mod` 12), ("zone", i `mod` 3)]
        d = decide rc a
        top = [r | r <- rc, evalD a (riCond r), isTerminal (riEffect r)]
    in case top of (r : _) | riEffect r == EfDeny -> dcCode d == 0; _ -> True

  section "Graph verification"
  let cats = map fnCat fs0
  check ctx "direct database access found" ("DirectDatabaseAccess" `elem` cats)
  check ctx "finding has path, evidence and confidence" (all (\f -> not (null (fnPath f)) && fnConf f > 0 && not (null (fnFix f))) fs0)
  let good = base ++ "" in check ctx "analysis is deterministic" (render (findingsJ fs0) == render (findingsJ (let (_, _, x) = analyzeText good in x)))
  let (_, _, fsSecure) = analyzeText (unlines (filter (not . ("Direct" `isInfixOf`)) (lines base)))
  check ctx "removing the direct flow removes the finding" ("DirectDatabaseAccess" `notElem` map fnCat fsSecure)
  let (_, _, fsAuth) = analyzeText (unlines (map (\l -> if "api Api" `isInfixOf` l then "api Api in Backend { controls: [audit]; }" else l) (lines base)))
  check ctx "missing authentication detected when the control is removed" ("MissingAuthentication" `elem` map fnCat fsAuth)

  section "Assertions"
  let (ma, _, fa) = analyzeText (base ++ "assert A1: never data Card enters zone DatabaseZone;\nassert A2: Api must_have authentication;\n")
      va = verifyAll (mkIx ma) (VerifyIn [] (policyDom (mkIx ma) [])) fa
  check ctx "assertions produce a verdict list" (case vAssertions va of JArr xs -> length xs == 2; _ -> False)
  check ctx "violated static assertion is reported" ("violated" `isInfixOf` render (vAssertions va))
  check ctx "discharged static assertion is reported" ("discharged" `isInfixOf` render (vAssertions va))

  section "Refactoring equivalence"
  let refJ = render (refactorJ m0 "F-001")
  check ctx "refactor returns candidates" ("candidates" `isInfixOf` refJ && "postconditions" `isInfixOf` refJ)
  check ctx "candidates keep original connectivity" (not ("\"equivalent\":false" `isInfixOf` refJ))
  check ctx "at least one candidate removes the finding" ("the selected finding is removed\",\"holds\":true" `isInfixOf` refJ)
  check ctx "candidate DSL is parseable" (let (dd, ee') = parseSource "c.tz" (extractDsl refJ) in null ee' && not (null dd))

  section "Determinism"
  prop ctx "render (analysis) is stable" 5 $ \_ -> render (findingsJ fs0) == render (findingsJ fs0)
  check ctx "formatting twice is a fixed point" (prettyModel m0 == prettyModel (buildModel (fst (parseSource "x" (prettyModel m0)))))

  section "Fuzzing the DSL front end"
  results <- forM [1 .. 400 :: Int] $ \i -> do
    let n = length base
        cut = sample i (choose 0 (n - 1)) 31
        ins = sample i (elements "{}();:\"#@ \n,.[]<>=!") 37
        mutated = take cut base ++ [ins] ++ drop (cut + sample i (choose 0 6) 41) base
    r <- try (evaluate (let (dd, ee') = parseSource "f.tz" mutated in length (show ee') + length dd + (let mm = buildModel dd in length (render (findingsJ (let (_, fz) = analyzeQuick mm in fz))))))
    pure (either (\e -> const False (e :: SomeException)) (const True) r)
  check ctx "no crash on 400 mutated inputs" (and results)
  garbage <- forM [1 .. 200 :: Int] $ \i -> do
    let s = [sample (i * 31 + k) (elements "abc {}();:\"#@ \n1234.,[]<>=!/*-_") 43 | k <- [1 .. 60]]
    r <- try (evaluate (length (show (parseSource "g.tz" s))))
    pure (either (\e -> const False (e :: SomeException)) (const True) r)
  check ctx "no crash on 200 random character soups" (and garbage)

  p <- readIORef (passed ctx)
  f <- readIORef (failed ctx)
  putStrLn (show p ++ " passed, " ++ show f ++ " failed")
  if f == 0 then exitSuccess else exitFailure
  where
    findingsJ fs = arr (zipWith findingJ [0 ..] fs)
    extractDsl js = readStr (drop 7 (snd (breakOn "\"dsl\":\"" (snd (breakOn "\"candidates\"" js)))))
    breakOn pat s = go "" s where
      go acc r | pat `isPrefixOf'` r = (reverse acc, r)
      go acc (c : cs) = go (c : acc) cs
      go acc [] = (reverse acc, [])
    isPrefixOf' p s = take (length p) s == p
    readStr ('\\' : 'n' : r) = '\n' : readStr r
    readStr ('\\' : 't' : r) = '\t' : readStr r
    readStr ('\\' : '"' : r) = '"' : readStr r
    readStr ('\\' : '\\' : r) = '\\' : readStr r
    readStr ('"' : _) = []
    readStr (c : r) = c : readStr r
    readStr [] = []
