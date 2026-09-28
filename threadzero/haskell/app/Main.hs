module Main (main) where

import Data.List (nub, sortOn)
import qualified Data.Map.Strict as M
import System.Environment (getArgs)
import System.Exit (exitWith, ExitCode(..))
import System.IO
import TZ.Analyzer
import TZ.Ast
import TZ.Expr
import TZ.Json
import TZ.Parser
import TZ.Policy
import TZ.Pretty
import TZ.Refactor
import TZ.Semantic
import TZ.Solver
import TZ.Types

version, ruleset :: String
version = "1.0.0"
ruleset = "tz-rules-1.0"

readInput :: FilePath -> IO String
readInput "-" = hSetEncoding stdin utf8 >> getContents
readInput p = do
  h <- openFile p ReadMode
  hSetEncoding h utf8
  s <- hGetContents h
  length s `seq` hClose h
  pure s

diagJ :: Diag -> J
diagJ d = obj
  [ ("severity", str (sevName (dSev d))), ("code", str (dCode d)), ("message", str (dMsg d))
  , ("file", str (pFile (dPos d))), ("line", jint (pLine (dPos d))), ("col", jint (pCol (dPos d)))
  , ("node", jmaybe str (dNode d)), ("hint", jmaybe str (dHint d)) ]

modelOf :: FilePath -> String -> (Model, [Diag])
modelOf file src = let (ds, es) = parseSource file src in (buildModel ds, es)

analyze :: FilePath -> String -> J
analyze file src = obj
  [ ("tool", obj [("name", str "threadzero-core"), ("version", str version), ("ruleset", str ruleset)])
  , ("project", obj [("name", str (moName m)), ("version", str (moVersion m)), ("timezone", str (moTz m)), ("imports", strs (moImports m))])
  , ("ok", jbool (null errors)), ("errorCount", jint (length errors))
  , ("diagnostics", arr (map diagJ allDiags))
  , ("ast", astJ m), ("symbols", symbolsJ ix), ("graph", graphJ ix)
  , ("findings", arr (zipWith findingJ [0 ..] fs))
  , ("properties", vProperties ver), ("assertions", vAssertions ver), ("constraints", vConstraints ver), ("obligations", vObligations ver)
  , ("policy", obj
      [ ("rules", rulesJ ix rules), ("tables", tablesJ ix), ("windows", windowsJ ix), ("runtimeChecks", runtimeChecksJ ix)
      , ("defaultEffect", str "deny"), ("conflicts", conflictsJ ix confs), ("optimizations", optimizationsJ opts)
      , ("coverage", coverageJ (policyCoverage ix dom rules)), ("tests", testsJ (genTests ix dom rules))
      , ("solver", str (solverName builtinSolver)), ("effectiveRules", jint (effectiveRuleCount ix)) ])
  , ("controlCoverage", controlCoverageJ ix), ("lineage", lineageJ ix)
  , ("propagation", arr [obj [("data", str n), ("declared", str (className ix a)), ("effective", str (className ix b)), ("derivedFrom", strs s)] | (n, a, b, s) <- propRows])
  , ("dependencies", dependenciesJ ix rules), ("validationPoints", validationPointsJ ix), ("guards", guardsJ ix)
  , ("metrics", metricsJ ix fs), ("simplifier", simplifierJ ix) ]
  where
    (m, parseDiags) = modelOf file src
    ix = mkIx m
    (rules, ruleDiags) = buildRules ix
    dom = policyDom ix rules
    (propDiags, propRows) = classPropagation ix
    confs = conflicts ix dom rules
    fs = findings ix rules confs
    ver = verifyAll ix (VerifyIn rules dom) fs
    opts = optimizations ix dom rules
    optDiags = [ (mkDiag SevOptimization ("TZ4" ++ optCode (opKind o)) (opPos o) (opMsg o)) { dHint = Just (opProposal o) } | o <- opts ]
    optCode k = case k of "DeadRule" -> "001"; "UnreachableRule" -> "002"; "RedundantCondition" -> "003"; "DuplicateRule" -> "004"; _ -> "000"
    findingDiags = [ withNode (maybe "" id (fnFlow f)) (mkDiag SevFinding (fnRule f) (fnPos f) (fnCat f ++ ": " ++ fnMsg f)) { dHint = Just (fnFix f) } | f <- fs ]
    baseDiags = parseDiags ++ checkModel ix ++ ruleDiags ++ policyDiags ix dom rules ++ propDiags ++ vDiags ver
    allDiags = sortOn key (baseDiags ++ findingDiags ++ optDiags ++ vAssertDiags ver)
    key d = (sevRank (dSev d), pFile (dPos d), pLine (dPos d), pCol (dPos d), dCode d, dMsg d)
    sevRank s = case s of SevError -> 0 :: Int; SevWarning -> 1; SevNotice -> 2; SevFinding -> 3; SevOptimization -> 4
    errors = [d | d <- baseDiags, dSev d == SevError]

main :: IO ()
main = do
  hSetEncoding stdout utf8
  hSetEncoding stderr utf8
  args <- getArgs
  case args of
    ["--version"] -> putStrLn ("threadzero-core " ++ version ++ " " ++ ruleset)
    ["parse", f] -> do
      src <- readInput f
      let (ds, es) = parseSource f src
      putStrLn (render (obj [("ok", jbool (null es)), ("diagnostics", arr (map diagJ es)), ("ast", astJ (buildModel ds))]))
    ["analyze", f] -> readInput f >>= putStrLn . render . analyze f
    ["fmt", f] -> do
      src <- readInput f
      let (m, es) = modelOf f src
      if null es then putStr (prettyModel m) else do
        hPutStrLn stderr (unlines [pFile (dPos d) ++ ":" ++ show (pLine (dPos d)) ++ ": " ++ dMsg d | d <- es])
        exitWith (ExitFailure 2)
    ["refactor", f, fid] -> do
      src <- readInput f
      let (m, _) = modelOf f src
      putStrLn (render (refactorJ m fid))
    ["smt", f, rid] -> do
      src <- readInput f
      let (m, _) = modelOf f src
          ix = mkIx m
          (rules, _) = buildRules ix
          dom = policyDom ix rules
      case [r | r <- rules, riPolicy r ++ "." ++ riName r == rid] of
        (r : _) -> putStr (smtLib dom (riCond r))
        [] -> hPutStrLn stderr ("unknown rule " ++ rid) >> exitWith (ExitFailure 2)
    _ -> do
      hPutStrLn stderr "usage: threadzero-core (--version | parse F | analyze F | fmt F | refactor F FINDING-ID | smt F POLICY.RULE)   (F may be - for stdin)"
      exitWith (ExitFailure 64)
