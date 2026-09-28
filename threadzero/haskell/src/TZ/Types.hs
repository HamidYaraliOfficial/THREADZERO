-- | Core types of THREADZERO: source positions, diagnostics, the Security AST
--   (declarations and the canonical Model), symbol indexes and builtin tables.
module TZ.Types where

import qualified Data.Map.Strict as M
import Data.Char (toLower)
import Data.List (sortOn, foldl')
import Data.Maybe (mapMaybe)

-- ---------------------------------------------------------------------------
-- Positions and diagnostics

-- | Source position. Positions never affect AST equality (roundtrip tests rely on it).
data Pos = Pos { pFile :: String, pLine :: Int, pCol :: Int } deriving (Show)
instance Eq Pos where _ == _ = True
instance Ord Pos where compare (Pos f l c) (Pos f' l' c') = compare (f, l, c) (f', l', c')

noPos :: Pos
noPos = Pos "" 0 0

data Severity = SevError | SevWarning | SevNotice | SevFinding | SevOptimization
  deriving (Eq, Ord, Show)

sevName :: Severity -> String
sevName s = case s of
  SevError -> "error"; SevWarning -> "warning"; SevNotice -> "notice"
  SevFinding -> "finding"; SevOptimization -> "optimization"

data Diag = Diag
  { dSev :: Severity, dCode :: String, dMsg :: String, dPos :: Pos
  , dNode :: Maybe String, dHint :: Maybe String
  } deriving (Eq, Show)

mkDiag :: Severity -> String -> Pos -> String -> Diag
mkDiag s c p m = Diag s c m p Nothing Nothing

withNode :: String -> Diag -> Diag
withNode n d = d { dNode = Just n }

withHint :: String -> Diag -> Diag
withHint h d = d { dHint = Just h }

-- ---------------------------------------------------------------------------
-- Values and properties

data Value
  = VId String | VStr String | VNum Int | VDur Int Char | VTime Int | VBool Bool | VList [Value]
  deriving (Eq, Show)

data Prop = Prop { prKey :: String, prPos :: Pos, prVal :: Value } deriving (Eq, Show)
type Props = [Prop]

getProp :: String -> Props -> Maybe Value
getProp k ps = case [prVal p | p <- ps, prKey p == k] of (v : _) -> Just v; [] -> Nothing

getPropPos :: String -> Props -> Maybe Pos
getPropPos k ps = case [prPos p | p <- ps, prKey p == k] of (v : _) -> Just v; [] -> Nothing

valNames :: Value -> [String]
valNames (VId s) = [s]
valNames (VList xs) = concatMap valNames xs
valNames _ = []

valText :: Value -> Maybe String
valText (VId s) = Just s
valText (VStr s) = Just s
valText _ = Nothing

valBool :: Value -> Maybe Bool
valBool (VBool b) = Just b
valBool (VId "true") = Just True
valBool (VId "false") = Just False
valBool _ = Nothing

valInt :: Value -> Maybe Int
valInt (VNum n) = Just n
valInt _ = Nothing

propNames :: String -> Props -> [String]
propNames k ps = maybe [] valNames (getProp k ps)

propBool :: String -> Bool -> Props -> Bool
propBool k d ps = maybe d (maybe d id . valBool) (getProp k ps)

propInt :: String -> Int -> Props -> Int
propInt k d ps = maybe d (maybe d id . valInt) (getProp k ps)

propText :: String -> Props -> Maybe String
propText k ps = getProp k ps >>= valText

durSeconds :: Int -> Char -> Int
durSeconds n u = n * case u of
  's' -> 1; 'm' -> 60; 'h' -> 3600; 'd' -> 86400; 'w' -> 604800; 'y' -> 31536000; _ -> 1

-- ---------------------------------------------------------------------------
-- Node kinds, effects, expressions

data NodeKind
  = KUser | KIdentity | KDevice | KApplication | KService | KApi | KDatabase | KQueue
  | KFileStore | KCloud | KSecret | KExternal | KAgent | KApproval
  deriving (Eq, Ord, Show, Enum, Bounded)

kindName :: NodeKind -> String
kindName k = case k of
  KUser -> "user"; KIdentity -> "identity"; KDevice -> "device"; KApplication -> "application"
  KService -> "service"; KApi -> "api"; KDatabase -> "database"; KQueue -> "queue"
  KFileStore -> "filestore"; KCloud -> "cloud"; KSecret -> "secret"; KExternal -> "external"
  KAgent -> "agent"; KApproval -> "approval"

kindFromName :: String -> Maybe NodeKind
kindFromName s = lookup s [(kindName k, k) | k <- [minBound .. maxBound]]

data Effect
  = EfAllow | EfDeny | EfRequireMfa | EfRequireApproval | EfRedact | EfEncrypt | EfAudit
  | EfRateLimit | EfTokenize | EfQuarantine | EfRequireTrustedZone
  deriving (Eq, Ord, Show, Enum, Bounded)

effectName :: Effect -> String
effectName e = case e of
  EfAllow -> "allow"; EfDeny -> "deny"; EfRequireMfa -> "require_mfa"
  EfRequireApproval -> "require_approval"; EfRedact -> "redact"; EfEncrypt -> "encrypt"
  EfAudit -> "audit"; EfRateLimit -> "rate_limit"; EfTokenize -> "tokenize"
  EfQuarantine -> "quarantine"; EfRequireTrustedZone -> "require_trusted_zone"

effectFromName :: String -> Maybe Effect
effectFromName s = lookup s [(effectName e, e) | e <- [minBound .. maxBound]]

isTerminal :: Effect -> Bool
isTerminal e = e == EfAllow || e == EfDeny

-- | Obligation bit of an effect in the ABI obligations mask.
effectBit :: Effect -> Int
effectBit e = 2 ^ fromEnum e

data CmpOp = OpEq | OpNe | OpGe | OpLe | OpGt | OpLt deriving (Eq, Ord, Show)

cmpText :: CmpOp -> String
cmpText o = case o of OpEq -> "=="; OpNe -> "!="; OpGe -> ">="; OpLe -> "<="; OpGt -> ">"; OpLt -> "<"

data Expr
  = XBool Bool | XNum Int | XStr String | XId Pos String | XAttr Pos String
  | XCmp Pos CmpOp Expr Expr | XIn Pos Expr [Expr]
  | XAnd Expr Expr | XOr Expr Expr | XNot Expr | XCall Pos String [Expr]
  deriving (Eq, Show)

data Rule = Rule
  { ruPos :: Pos, ruName :: String, ruEffect :: Effect, ruWhen :: Maybe Expr
  , ruReason :: Maybe String, ruObl :: [Effect], ruPrio :: Maybe Int
  } deriving (Eq, Show)

data Scope = ScGlobal | ScZone String | ScData String | ScResource String deriving (Eq, Show)

data PolicyDef = PolicyDef
  { plPos :: Pos, plName :: String, plVersion :: String, plPrio :: Int
  , plScope :: Scope, plExtends :: Maybe String, plRules :: [Rule]
  } deriving (Eq, Show)

data Assertion
  = AsNeverEnter String String
  | AsMustNot String String String
  | AsActionAudit String
  | AsNodeControl String String
  | AsSecureChannel (Maybe String)
  | AsNeverOp (Either String String) String
  | AsRequest Expr Effect
  deriving (Eq, Show)

data Constraint
  = CoMaxClass String String
  | CoNoFlow String String (Maybe String)
  | CoRequireControl String String String
  | CoMaxFanout String Int
  | CoAcyclicPolicies
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Declarations (parser output)

data Decl
  = DProject Pos String String String
  | DImport Pos String
  | DClass Pos String Int (Maybe String)
  | DZone Pos String Int (Maybe String) (Maybe String) Props
  | DRole Pos String
  | DEnv Pos String
  | DAction Pos String
  | DLocation Pos String
  | DData Pos String String Props
  | DNode Pos NodeKind String String Props
  | DAssign Pos String String
  | DWindow Pos String Props
  | DFlow Pos String String String [String] String Props
  | DBoundary Pos String String Props
  | DPolicy PolicyDef
  | DAssert Pos String Assertion
  | DConstraint Pos String Constraint
  | DDeclassify Pos String Props
  | DSeparation Pos String Props
  | DDelegate Pos String Props
  | DProperty Pos String Bool
  | DWorkflow Pos String Props
  deriving (Eq, Show)

-- ---------------------------------------------------------------------------
-- Canonical model (the Security AST after grouping)

type Named = (String, Pos)

data ClassR = ClassR { cPos :: Pos, cName :: String, cRank :: Int, cExt :: Maybe String } deriving (Eq, Show)
data ZoneR = ZoneR { zPos :: Pos, zName :: String, zId :: Int, zTrust :: Int, zKindS :: String, zMax :: Maybe String, zProps :: Props } deriving (Eq, Show)
data DataR = DataR { dtPos :: Pos, dtName :: String, dtId :: Int, dtClass :: String, dtProps :: Props } deriving (Eq, Show)
data NodeR = NodeR { nPos :: Pos, nKind :: NodeKind, nName :: String, nId :: Int, nZone :: String, nProps :: Props } deriving (Eq, Show)
data FlowR = FlowR { fPos :: Pos, fName :: String, fFrom :: String, fTo :: String, fData :: [String], fOp :: String, fProps :: Props } deriving (Eq, Show)
data PropDecl = PropDecl { pdPos :: Pos, pdName :: String, pdProps :: Props } deriving (Eq, Show)
data BoundR = BoundR { bPos :: Pos, bFrom :: String, bTo :: String, bProps :: Props } deriving (Eq, Show)
data AssertR = AssertR { asPos :: Pos, asName :: String, asBody :: Assertion } deriving (Eq, Show)
data ConstrR = ConstrR { csPos :: Pos, csName :: String, csBody :: Constraint } deriving (Eq, Show)

data Model = Model
  { moName :: String, moVersion :: String, moTz :: String
  , moImports :: [String]
  , moClasses :: [ClassR], moZones :: [ZoneR]
  , moRoles :: [Named], moEnvs :: [Named], moActions :: [Named], moLocs :: [Named]
  , moData :: [DataR], moNodes :: [NodeR], moAssigns :: [(String, String, Pos)]
  , moWindows :: [PropDecl], moFlows :: [FlowR], moBounds :: [BoundR]
  , moPolicies :: [PolicyDef], moAsserts :: [AssertR], moConstraints :: [ConstrR]
  , moDeclass :: [PropDecl], moSeps :: [PropDecl], moDelegs :: [PropDecl]
  , moPropsOn :: [(String, Bool, Pos)], moWorkflows :: [PropDecl]
  } deriving (Eq, Show)

emptyModel :: Model
emptyModel = Model "untitled" "0.0.0" "UTC" [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []

-- | Group declarations into a Model, numbering zones / data / nodes by declaration order.
buildModel :: [Decl] -> Model
buildModel ds = renumber base
  where
    base = foldl' step emptyModel ds
    step m d = case d of
      DProject _ n v tz -> m { moName = n, moVersion = v, moTz = tz }
      DImport _ p -> m { moImports = moImports m ++ [p] }
      DClass p n r e -> m { moClasses = moClasses m ++ [ClassR p n r e] }
      DZone p n t k mc pr -> m { moZones = moZones m ++ [ZoneR p n 0 t (maybe (defaultKind n) id k) mc pr] }
      DRole p n -> m { moRoles = moRoles m ++ [(n, p)] }
      DEnv p n -> m { moEnvs = moEnvs m ++ [(n, p)] }
      DAction p n -> m { moActions = moActions m ++ [(n, p)] }
      DLocation p n -> m { moLocs = moLocs m ++ [(n, p)] }
      DData p n c pr -> m { moData = moData m ++ [DataR p n 0 c pr] }
      DNode p k n z pr -> m { moNodes = moNodes m ++ [NodeR p k n 0 z pr] }
      DAssign p i r -> m { moAssigns = moAssigns m ++ [(i, r, p)] }
      DWindow p n pr -> m { moWindows = moWindows m ++ [PropDecl p n pr] }
      DFlow p n a b ds' op pr -> m { moFlows = moFlows m ++ [FlowR p n a b ds' op pr] }
      DBoundary p a b pr -> m { moBounds = moBounds m ++ [BoundR p a b pr] }
      DPolicy pd -> m { moPolicies = moPolicies m ++ [pd] }
      DAssert p n a -> m { moAsserts = moAsserts m ++ [AssertR p n a] }
      DConstraint p n c -> m { moConstraints = moConstraints m ++ [ConstrR p n c] }
      DDeclassify p n pr -> m { moDeclass = moDeclass m ++ [PropDecl p n pr] }
      DSeparation p n pr -> m { moSeps = moSeps m ++ [PropDecl p n pr] }
      DDelegate p n pr -> m { moDelegs = moDelegs m ++ [PropDecl p n pr] }
      DProperty p n b -> m { moPropsOn = moPropsOn m ++ [(n, b, p)] }
      DWorkflow p n pr -> m { moWorkflows = moWorkflows m ++ [PropDecl p n pr] }

-- | Re-assign dense ids after any structural change.
renumber :: Model -> Model
renumber m = m
  { moZones = [z { zId = i } | (i, z) <- zip [0 ..] (moZones m)]
  , moData = [d { dtId = i } | (i, d) <- zip [0 ..] (moData m)]
  , moNodes = [n { nId = i } | (i, n) <- zip [0 ..] (moNodes m)]
  }

defaultKind :: String -> String
defaultKind n = if n `elem` zoneKinds then n else "Custom"

-- ---------------------------------------------------------------------------
-- Builtin tables

builtinClasses :: [(String, Int)]
builtinClasses =
  [ ("Public", 0), ("Internal", 1), ("Confidential", 2), ("Restricted", 3), ("Financial", 3)
  , ("Personal", 3), ("HighlySensitive", 4), ("Credential", 5), ("Secret", 5) ]

builtinActions :: [String]
builtinActions =
  ["Create", "Read", "Write", "Transform", "Enrich", "Copy", "Export", "Publish", "Subscribe", "Cache", "Log", "Delete"]

zoneKinds :: [String]
zoneKinds =
  [ "PublicInternet", "Browser", "MobileClient", "InternalNetwork", "ServiceMesh", "Backend", "DatabaseZone"
  , "AdminZone", "PartnerZone", "ThirdPartyZone", "SecureProcessingZone", "SecretZone", "UntrustedZone", "Custom" ]

controlNames :: [String]
controlNames =
  [ "authentication", "authorization", "encryption", "integrity_check", "schema_validation"
  , "input_validation", "output_filtering", "approval", "rate_limit", "audit", "token_exchange"
  , "data_minimization", "redaction", "monitoring", "isolation", "tokenization", "mfa" ]

controlBit :: String -> Int
controlBit c = maybe 0 (2 ^) (lookup c (zip controlNames [0 :: Int ..]))

controlMask :: [String] -> Int
controlMask = foldl' (\a c -> a + (if a `div` controlBit c `mod` 2 == 1 then 0 else controlBit c)) 0

maskControls :: Int -> [String]
maskControls mk = [c | c <- controlNames, (mk `div` controlBit c) `mod` 2 == 1]

reservedWords :: [String]
reservedWords =
  [ "project", "import", "classification", "zone", "role", "env", "action", "location", "data", "assign"
  , "window", "flow", "boundary", "policy", "rule", "assert", "constraint", "declassify", "separation"
  , "delegate", "property", "workflow", "template", "apply", "and", "or", "not", "in", "when", "true", "false" ]
  ++ map kindName [minBound .. maxBound]

-- | Attribute table: expression path -> (type, ABI slot).
data Ty = TyRole | TyZone | TyAction | TyNode | TyKind | TyData | TyClass | TyBool | TyInt | TyEnv | TyLoc | TyZKind
  deriving (Eq, Show)

tyName :: Ty -> String
tyName t = case t of
  TyRole -> "Role"; TyZone -> "Zone"; TyAction -> "Action"; TyNode -> "Node"; TyKind -> "NodeKind"
  TyData -> "Data"; TyClass -> "Classification"; TyBool -> "Bool"; TyInt -> "Int"; TyEnv -> "Environment"
  TyLoc -> "Location"; TyZKind -> "ZoneKind"

attrTable :: [(String, (Ty, String))]
attrTable =
  [ ("subject", (TyNode, "subj")), ("subject.role", (TyRole, "roles")), ("subject.zone", (TyZone, "szone"))
  , ("subject.mfa", (TyBool, "mfa")), ("subject.device_trust", (TyInt, "dtrust"))
  , ("subject.clearance", (TyClass, "clearance")), ("resource", (TyNode, "res"))
  , ("resource.kind", (TyKind, "reskind")), ("resource.zone", (TyZone, "rzone")), ("action", (TyAction, "action"))
  , ("data", (TyData, "data")), ("data.classification", (TyClass, "class")), ("zone", (TyZone, "zone"))
  , ("zone.trust", (TyInt, "ztrust")), ("zone.kind", (TyZKind, "zkind")), ("env", (TyEnv, "env"))
  , ("context.location", (TyLoc, "loc")), ("context.time", (TyInt, "mow"))
  , ("context.approved", (TyBool, "approved")), ("context.emergency", (TyBool, "emergency"))
  , ("context.secure_channel", (TyBool, "secure")), ("context.tenant_match", (TyBool, "tenant")) ]

slotNames :: [String]
slotNames = map (snd . snd) attrTable

-- ---------------------------------------------------------------------------
-- Findings

data Level = LInfo | LLow | LMedium | LHigh | LCritical deriving (Eq, Ord, Show, Enum, Bounded)

levelName :: Level -> String
levelName l = case l of LInfo -> "Info"; LLow -> "Low"; LMedium -> "Medium"; LHigh -> "High"; LCritical -> "Critical"

data Finding = Finding
  { fnCat :: String, fnRule :: String, fnLevel :: Level, fnConf :: Double
  , fnTitle :: String, fnMsg :: String, fnEvidence :: [String], fnPath :: [String]
  , fnAffected :: [String], fnFlow :: Maybe String, fnData :: Maybe String
  , fnFix :: String, fnPos :: Pos, fnMissing :: [String]
  } deriving (Eq, Show)

-- | Root flow name (refactoring derives flows as "<root>__<suffix>").
rootName :: String -> String
rootName s = go s where
  go ('_' : '_' : _) = []
  go (c : cs) = c : go cs
  go [] = []

fingerprint :: Finding -> String
fingerprint f = fnCat f ++ "|" ++ (case fnFlow f of Just fl -> rootName fl; Nothing -> concatMap (++ ",") (fnAffected f)) ++ "|" ++ maybe "" id (fnData f)

-- ---------------------------------------------------------------------------
-- Symbol index

data Ix = Ix
  { ixModel :: Model
  , ixZone :: M.Map String ZoneR, ixNode :: M.Map String NodeR, ixData :: M.Map String DataR
  , ixFlow :: M.Map String FlowR, ixClass :: M.Map String Int, ixRole :: M.Map String Int
  , ixAction :: M.Map String Int, ixEnv :: M.Map String Int, ixLoc :: M.Map String Int
  , ixWin :: M.Map String (Int, [(Int, Int)]), ixPolicy :: M.Map String PolicyDef
  }

allClasses :: Model -> [(String, Int)]
allClasses m = builtinClasses ++ [(cName c, cRank c) | c <- moClasses m]

allActions :: Model -> [String]
allActions m = builtinActions ++ map fst (moActions m)

mkIx :: Model -> Ix
mkIx m = Ix
  { ixModel = m
  , ixZone = M.fromList [(zName z, z) | z <- moZones m]
  , ixNode = M.fromList [(nName n, n) | n <- moNodes m]
  , ixData = M.fromList [(dtName d, d) | d <- moData m]
  , ixFlow = M.fromList [(fName f, f) | f <- moFlows m]
  , ixClass = M.fromList (allClasses m)
  , ixRole = M.fromList (zip (map fst (moRoles m)) [0 ..])
  , ixAction = M.fromList (zip (allActions m) [0 ..])
  , ixEnv = M.fromList (zip (map fst (moEnvs m)) [0 ..])
  , ixLoc = M.fromList (zip (map fst (moLocs m)) [0 ..])
  , ixWin = M.fromList [(pdName w, (i, windowRanges (pdProps w))) | (i, w) <- zip [0 ..] (moWindows m)]
  , ixPolicy = M.fromList [(plName p, p) | p <- moPolicies m]
  }

className :: Ix -> Int -> String
className ix r = case [n | (n, k) <- allClasses (ixModel ix), k == r] of (n : _) -> n; [] -> "Rank" ++ show r

dataRank :: Ix -> String -> Int
dataRank ix d = maybe 0 id (M.lookup d (ixData ix) >>= \dr -> M.lookup (dtClass dr) (ixClass ix))

zoneTrust :: Ix -> String -> Int
zoneTrust ix z = maybe 0 zTrust (M.lookup z (ixZone ix))

nodeZone :: Ix -> String -> Maybe ZoneR
nodeZone ix n = M.lookup n (ixNode ix) >>= \nr -> M.lookup (nZone nr) (ixZone ix)

-- ---------------------------------------------------------------------------
-- Time windows (minute-of-week, Monday 00:00 = 0)

windowRanges :: Props -> [(Int, Int)]
windowRanges ps = normalize (concatMap rng days)
  where
    days = case getProp "days" ps of
      Just (VId "weekdays") -> [0 .. 4]
      Just (VId "weekends") -> [5, 6]
      Just (VId "daily") -> [0 .. 6]
      Just (VList xs) -> mapMaybe (\v -> valText v >>= dayIdx) xs
      Just (VId d) -> maybe [0 .. 6] pure (dayIdx d)
      _ -> [0 .. 6]
    from = case getProp "from" ps of Just (VTime t) -> t; _ -> 0
    to = case getProp "to" ps of Just (VTime t) -> t; _ -> 1440
    rng d
      | to > from = [(d * 1440 + from, d * 1440 + to)]
      | to == from = [(d * 1440, (d + 1) * 1440)]
      | otherwise = [(d * 1440 + from, (d + 1) * 1440)] ++ [(((d + 1) `mod` 7) * 1440, ((d + 1) `mod` 7) * 1440 + to) | to > 0]
    normalize = mergeR . sortOn fst
    mergeR ((a, b) : (c, d) : r) | c <= b = mergeR ((a, max b d) : r)
    mergeR (x : r) = x : mergeR r
    mergeR [] = []

dayIdx :: String -> Maybe Int
dayIdx s = lookup (map toLower s)
  [ ("mon", 0), ("monday", 0), ("tue", 1), ("tuesday", 1), ("wed", 2), ("wednesday", 2), ("thu", 3)
  , ("thursday", 3), ("fri", 4), ("friday", 4), ("sat", 5), ("saturday", 5), ("sun", 6), ("sunday", 6) ]

-- ---------------------------------------------------------------------------
-- Suggestions ("did you mean")

editDistance :: String -> String -> Int
editDistance a b = last (foldl' row [0 .. length a] b)
  where
    row prev@(p : ps) c = scanl compute (p + 1) (zip3 a prev ps)
      where compute left (ac, diag, up) = minimum [up + 1, left + 1, diag + (if ac == c then 0 else 1)]
    row [] _ = []

suggest :: String -> [String] -> Maybe String
suggest s cands = case sortOn fst [(editDistance (map toLower s) (map toLower c), c) | c <- cands] of
  ((d, c) : _) | d <= max 1 (length s `div` 3) -> Just c
  _ -> Nothing
