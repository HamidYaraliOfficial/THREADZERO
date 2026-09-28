-- | Recursive-descent parser for the THREADZERO Security DSL with multi-error recovery.
module TZ.Parser (parseSource, parseTokens) where

import TZ.Lexer
import TZ.Template
import TZ.Types

newtype P a = P { runP :: [Token] -> Either Diag (a, [Token]) }

instance Functor P where
  fmap f (P g) = P $ \ts -> case g ts of Left e -> Left e; Right (a, r) -> Right (f a, r)
instance Applicative P where
  pure a = P $ \ts -> Right (a, ts)
  P f <*> P g = P $ \ts -> case f ts of
    Left e -> Left e
    Right (h, r) -> case g r of Left e -> Left e; Right (a, r') -> Right (h a, r')
instance Monad P where
  P g >>= f = P $ \ts -> case g ts of Left e -> Left e; Right (a, r) -> runP (f a) r

peek :: P Token
peek = P $ \ts -> case ts of
  (t : _) -> Right (t, ts)
  [] -> Left (mkDiag SevError "TZ1002" noPos "unexpected end of input")

advance :: P Token
advance = P $ \ts -> case ts of
  [t@(Token _ TEOF)] -> Right (t, ts)
  (t : r) -> Right (t, r)
  [] -> Left (mkDiag SevError "TZ1002" noPos "unexpected end of input")

failAt :: Pos -> String -> P a
failAt p m = P $ \_ -> Left (mkDiag SevError "TZ1002" p m)

expected :: String -> P a
expected what = do
  t <- peek
  failAt (tkPos t) ("expected " ++ what ++ ", found " ++ showTok (tkTok t))

sym :: String -> P Pos
sym s = do
  t <- peek
  case tkTok t of
    TSym x | x == s -> advance >> pure (tkPos t)
    _ -> expected ("'" ++ s ++ "'")

ident :: P (Pos, String)
ident = do
  t <- peek
  case tkTok t of
    TId n -> advance >> pure (tkPos t, n)
    _ -> expected "an identifier"

name :: P String
name = snd <$> ident

kw :: String -> P Pos
kw k = do
  t <- peek
  case tkTok t of
    TId x | x == k -> advance >> pure (tkPos t)
    _ -> expected ("'" ++ k ++ "'")

pString :: P String
pString = do
  t <- peek
  case tkTok t of
    TStr s -> advance >> pure s
    _ -> expected "a string literal"

pNumber :: P Int
pNumber = do
  t <- peek
  case tkTok t of
    TNum n -> advance >> pure n
    _ -> expected "a number"

-- ---------------------------------------------------------------------------
-- Values and property blocks

pValue :: P Value
pValue = do
  t <- peek
  case tkTok t of
    TId "true" -> advance >> pure (VBool True)
    TId "false" -> advance >> pure (VBool False)
    TId n -> advance >> pure (VId n)
    TStr s -> advance >> pure (VStr s)
    TNum n -> advance >> pure (VNum n)
    TDur n u -> advance >> pure (VDur n u)
    TTime m -> advance >> pure (VTime m)
    TSym "[" -> advance >> (VList <$> listItems)
    _ -> expected "a value"
  where
    listItems = do
      t <- peek
      case tkTok t of
        TSym "]" -> advance >> pure []
        _ -> do
          v <- pValue
          t2 <- peek
          case tkTok t2 of
            TSym "," -> advance >> ((v :) <$> listItems)
            TSym "]" -> advance >> pure [v]
            _ -> expected "',' or ']'"

pProps :: P Props
pProps = sym "{" >> loop []
  where
    loop acc = do
      t <- peek
      case tkTok t of
        TSym "}" -> advance >> pure (reverse acc)
        TId _ -> do
          (p, k) <- ident
          _ <- sym ":"
          v <- pValue
          _ <- sym ";"
          loop (Prop k p v : acc)
        _ -> expected "a property name or '}'"

blockOrSemi :: P Props
blockOrSemi = do
  t <- peek
  case tkTok t of
    TSym "{" -> pProps
    _ -> sym ";" >> pure []

-- ---------------------------------------------------------------------------
-- Expressions

pExpr :: P Expr
pExpr = pAnd >>= orLoop
  where
    orLoop a = do
      t <- peek
      case tkTok t of
        TId "or" -> advance >> pAnd >>= orLoop . XOr a
        TSym "||" -> advance >> pAnd >>= orLoop . XOr a
        _ -> pure a

pAnd :: P Expr
pAnd = pNot >>= andLoop
  where
    andLoop a = do
      t <- peek
      case tkTok t of
        TId "and" -> advance >> pNot >>= andLoop . XAnd a
        TSym "&&" -> advance >> pNot >>= andLoop . XAnd a
        _ -> pure a

pNot :: P Expr
pNot = do
  t <- peek
  case tkTok t of
    TId "not" -> advance >> (XNot <$> pNot)
    TSym "!" -> advance >> (XNot <$> pNot)
    _ -> pCmp

pCmp :: P Expr
pCmp = do
  a <- pTerm
  t <- peek
  let p = tkPos t
      bin o = advance >> pTerm >>= \b -> pure (XCmp p o a b)
  case tkTok t of
    TSym "==" -> bin OpEq
    TSym "!=" -> bin OpNe
    TSym ">=" -> bin OpGe
    TSym "<=" -> bin OpLe
    TSym ">" -> bin OpGt
    TSym "<" -> bin OpLt
    TId "in" -> do
      _ <- advance
      _ <- sym "["
      xs <- items
      pure (XIn p a xs)
    _ -> pure a
  where
    items = do
      t <- peek
      case tkTok t of
        TSym "]" -> advance >> pure []
        _ -> do
          x <- pTerm
          t2 <- peek
          case tkTok t2 of
            TSym "," -> advance >> ((x :) <$> items)
            TSym "]" -> advance >> pure [x]
            _ -> expected "',' or ']'"

pTerm :: P Expr
pTerm = do
  t <- peek
  let p = tkPos t
  case tkTok t of
    TSym "(" -> do { _ <- advance; e <- pExpr; _ <- sym ")"; pure e }
    TNum n -> advance >> pure (XNum n)
    TTime m -> advance >> pure (XNum m)
    TStr s -> advance >> pure (XStr s)
    TId "true" -> advance >> pure (XBool True)
    TId "false" -> advance >> pure (XBool False)
    TId n -> do
      _ <- advance
      path <- dots n
      t2 <- peek
      case tkTok t2 of
        TSym "(" | '.' `notElem` path -> do
          _ <- advance
          args <- callArgs
          pure (XCall p path args)
        _ | path `elem` map fst attrTable -> pure (XAttr p path)
          | '.' `elem` path ->
              failAt p ("unknown attribute '" ++ path ++ "'" ++ maybe "" (\s -> " (did you mean '" ++ s ++ "'?)") (suggest path (map fst attrTable)))
          | otherwise -> pure (XId p path)
    _ -> expected "an expression"
  where
    dots acc = do
      t <- peek
      case tkTok t of
        TSym "." -> do
          _ <- advance
          (_, n) <- ident
          dots (acc ++ "." ++ n)
        _ -> pure acc
    callArgs = do
      t <- peek
      case tkTok t of
        TSym ")" -> advance >> pure []
        _ -> do
          e <- pExpr
          t2 <- peek
          case tkTok t2 of
            TSym "," -> advance >> ((e :) <$> callArgs)
            TSym ")" -> advance >> pure [e]
            _ -> expected "',' or ')'"

-- ---------------------------------------------------------------------------
-- Declarations

parseDecl :: P Decl
parseDecl = do
  t <- peek
  case tkTok t of
    TId "project" -> pProject
    TId "import" -> do { p <- kw "import"; s <- pString; _ <- sym ";"; pure (DImport p s) }
    TId "classification" -> pClass
    TId "zone" -> pZone
    TId "role" -> simple DRole "role"
    TId "env" -> simple DEnv "env"
    TId "action" -> simple DAction "action"
    TId "location" -> simple DLocation "location"
    TId "data" -> pData
    TId "assign" -> do { p <- kw "assign"; i <- name; _ <- kw "role"; r <- name; _ <- sym ";"; pure (DAssign p i r) }
    TId "window" -> propDecl DWindow "window"
    TId "flow" -> pFlow
    TId "boundary" -> do { p <- kw "boundary"; a <- name; _ <- sym "->"; b <- name; pr <- blockOrSemi; pure (DBoundary p a b pr) }
    TId "policy" -> pPolicy
    TId "assert" -> pAssert
    TId "constraint" -> pConstraint
    TId "declassify" -> propDecl DDeclassify "declassify"
    TId "separation" -> propDecl DSeparation "separation"
    TId "delegate" -> propDecl DDelegate "delegate"
    TId "workflow" -> propDecl DWorkflow "workflow"
    TId "property" -> do
      p <- kw "property"
      n <- name
      (sp, s) <- ident
      b <- case s of
        "on" -> pure True
        "off" -> pure False
        _ -> failAt sp "expected 'on' or 'off'"
      _ <- sym ";"
      pure (DProperty p n b)
    TId k | Just nk <- kindFromName k -> do
      p <- kw k
      n <- name
      _ <- kw "in"
      z <- name
      pr <- blockOrSemi
      pure (DNode p nk n z pr)
    _ -> failAt (tkPos t) ("unexpected " ++ showTok (tkTok t) ++ "; expected a declaration keyword (zone, data, service, flow, policy, assert, ...)")
  where
    simple mk k = do { p <- kw k; n <- name; _ <- sym ";"; pure (mk p n) }
    propDecl mk k = do { p <- kw k; n <- name; pr <- pProps; pure (mk p n pr) }

pProject :: P Decl
pProject = do
  p <- kw "project"
  n <- pString
  loop p n "0.0.0" "UTC"
  where
    loop p n v tz = do
      t <- peek
      case tkTok t of
        TId "version" -> advance >> pString >>= \v' -> loop p n v' tz
        TId "timezone" -> advance >> pString >>= \z -> loop p n v z
        _ -> sym ";" >> pure (DProject p n v tz)

pClass :: P Decl
pClass = do
  p <- kw "classification"
  n <- name
  _ <- kw "rank"
  r <- pNumber
  t <- peek
  e <- case tkTok t of
    TId "extends" -> advance >> (Just <$> name)
    _ -> pure Nothing
  _ <- sym ";"
  pure (DClass p n r e)

pZone :: P Decl
pZone = do
  p <- kw "zone"
  n <- name
  _ <- kw "trust"
  tr <- pNumber
  loop p n tr Nothing Nothing
  where
    loop p n tr k mc = do
      t <- peek
      case tkTok t of
        TId "kind" -> advance >> name >>= \k' -> loop p n tr (Just k') mc
        TId "max_class" -> advance >> name >>= \c -> loop p n tr k (Just c)
        _ -> blockOrSemi >>= \pr -> pure (DZone p n tr k mc pr)

pData :: P Decl
pData = do
  p <- kw "data"
  n <- name
  _ <- kw "class"
  c <- name
  pr <- blockOrSemi
  pure (DData p n c pr)

pFlow :: P Decl
pFlow = do
  p <- kw "flow"
  n <- name
  _ <- kw "from"
  a <- name
  _ <- kw "to"
  b <- name
  _ <- kw "carries"
  t <- peek
  ds <- case tkTok t of
    TSym "[" -> advance >> bracketed
    _ -> commaList
  _ <- kw "op"
  o <- name
  pr <- blockOrSemi
  pure (DFlow p n a b ds o pr)
  where
    commaList = do
      d <- name
      t <- peek
      case tkTok t of
        TSym "," -> advance >> ((d :) <$> commaList)
        _ -> pure [d]
    bracketed = do
      d <- name
      t <- peek
      case tkTok t of
        TSym "," -> advance >> ((d :) <$> bracketed)
        TSym "]" -> advance >> pure [d]
        _ -> expected "',' or ']'"

pPolicy :: P Decl
pPolicy = do
  p <- kw "policy"
  n <- name
  (ver, prio, sc, ext) <- header "1.0.0" 100 ScGlobal Nothing
  _ <- sym "{"
  rs <- rules []
  pure (DPolicy (PolicyDef p n ver prio sc ext rs))
  where
    header v pr sc ex = do
      t <- peek
      case tkTok t of
        TId "version" -> advance >> pString >>= \v' -> header v' pr sc ex
        TId "priority" -> advance >> pNumber >>= \pr' -> header v pr' sc ex
        TId "extends" -> advance >> name >>= \e -> header v pr sc (Just e)
        TId "scope" -> do
          _ <- advance
          (sp, s) <- ident
          sc' <- case s of
            "global" -> pure ScGlobal
            "zone" -> ScZone <$> name
            "data" -> ScData <$> name
            "resource" -> ScResource <$> name
            _ -> failAt sp "expected scope 'global', 'zone <Zone>', 'data <Data>' or 'resource <Node>'"
          header v pr sc' ex
        _ -> pure (v, pr, sc, ex)
    rules acc = do
      t <- peek
      case tkTok t of
        TSym "}" -> advance >> pure (reverse acc)
        TId "rule" -> pRule >>= \r -> rules (r : acc)
        _ -> expected "'rule' or '}'"

pRule :: P Rule
pRule = do
  p <- kw "rule"
  n <- name
  _ <- sym ":"
  (ep, en) <- ident
  eff <- maybe (failAt ep ("unknown effect '" ++ en ++ "'; expected one of: " ++ unwords (map effectName [minBound .. maxBound]))) pure (effectFromName en)
  loop (Rule p n eff Nothing Nothing [] Nothing)
  where
    loop r = do
      t <- peek
      case tkTok t of
        TSym ";" -> advance >> pure r
        TId "when" -> advance >> pExpr >>= \e -> loop r { ruWhen = Just e }
        TId "reason" -> advance >> pString >>= \s -> loop r { ruReason = Just s }
        TId "priority" -> advance >> pNumber >>= \k -> loop r { ruPrio = Just k }
        TId "obligations" -> do
          _ <- advance
          _ <- sym "["
          os <- effs
          loop r { ruObl = os }
        _ -> expected "'when', 'reason', 'obligations', 'priority' or ';'"
    effs = do
      t <- peek
      case tkTok t of
        TSym "]" -> advance >> pure []
        _ -> do
          (ep, en) <- ident
          e <- maybe (failAt ep ("unknown obligation '" ++ en ++ "'")) pure (effectFromName en)
          t2 <- peek
          case tkTok t2 of
            TSym "," -> advance >> ((e :) <$> effs)
            TSym "]" -> advance >> pure [e]
            _ -> expected "',' or ']'"

pAssert :: P Decl
pAssert = do
  p <- kw "assert"
  n <- name
  _ <- sym ":"
  t <- peek
  body <- case tkTok t of
    TId "never" -> advance >> never
    TId "action" -> do { _ <- advance; a <- name; _ <- kw "must"; _ <- kw "audit"; pure (AsActionAudit a) }
    TId "request" -> do
      _ <- advance
      e <- pExpr
      _ <- kw "must"
      (ep, en) <- ident
      case en of
        "deny" -> pure (AsRequest e EfDeny)
        "allow" -> pure (AsRequest e EfAllow)
        _ -> failAt ep "expected 'deny' or 'allow'"
    TId "flow" -> do { _ <- advance; f <- name; _ <- kw "must"; _ <- kw "secure_channel"; pure (AsSecureChannel (Just f)) }
    TId "all" -> do { _ <- advance; _ <- kw "flows"; _ <- kw "must"; _ <- kw "secure_channel"; pure (AsSecureChannel Nothing) }
    TId a -> do
      _ <- advance
      t2 <- peek
      case tkTok t2 of
        TId "must_not" -> do { _ <- advance; o <- name; b <- name; pure (AsMustNot a o b) }
        TId "must_have" -> do { _ <- advance; c <- name; pure (AsNodeControl a c) }
        _ -> expected "'must_not' or 'must_have'"
    _ -> expected "an assertion form (never, action, request, flow, all, or a node name)"
  _ <- sym ";"
  pure (DAssert p n body)
  where
    never = do
      t <- peek
      case tkTok t of
        TId "data" -> do
          _ <- advance
          d <- name
          t2 <- peek
          case tkTok t2 of
            TId "enters" -> do { _ <- advance; _ <- kw "zone"; z <- name; pure (AsNeverEnter d z) }
            TId "op" -> do { _ <- advance; o <- name; pure (AsNeverOp (Left d) o) }
            _ -> expected "'enters' or 'op'"
        TId "class" -> do { _ <- advance; c <- name; _ <- kw "op"; o <- name; pure (AsNeverOp (Right c) o) }
        _ -> expected "'data' or 'class'"

pConstraint :: P Decl
pConstraint = do
  p <- kw "constraint"
  n <- name
  _ <- sym ":"
  (kp, k) <- ident
  body <- case k of
    "max_class" -> CoMaxClass <$> name <*> name
    "no_flow" -> do
      a <- name
      b <- name
      t <- peek
      c <- case tkTok t of
        TId "carrying" -> advance >> (Just <$> name)
        _ -> pure Nothing
      pure (CoNoFlow a b c)
    "require_control" -> do
      c <- name
      _ <- kw "on"
      a <- name
      _ <- sym "->"
      b <- name
      pure (CoRequireControl c a b)
    "max_fanout" -> CoMaxFanout <$> name <*> pNumber
    "acyclic_policies" -> pure CoAcyclicPolicies
    _ -> failAt kp ("unknown constraint form '" ++ k ++ "' (max_class, no_flow, require_control, max_fanout, acyclic_policies)")
  _ <- sym ";"
  pure (DConstraint p n body)

-- ---------------------------------------------------------------------------
-- Entry points with recovery

parseTokens :: [Token] -> ([Decl], [Diag])
parseTokens = loop [] []
  where
    loop ds es ts = case ts of
      (Token _ TEOF : _) -> (reverse ds, reverse es)
      [] -> (reverse ds, reverse es)
      _ -> case runP parseDecl ts of
        Right (d, ts') -> loop (d : ds) es ts'
        Left e -> loop ds (e : es) (skipDecl ts)

skipDecl :: [Token] -> [Token]
skipDecl ts = go (0 :: Int) (drop 1 ts)
  where
    go d r = case r of
      [] -> []
      (Token _ TEOF : _) -> r
      (Token _ (TSym "{") : r') -> go (d + 1) r'
      (Token _ (TSym "}") : r') | d <= 1 -> r'
                                | otherwise -> go (d - 1) r'
      (Token _ (TSym ";") : r') | d == 0 -> r'
      (_ : r') -> go d r'

-- | Lex + expand templates + parse. The first argument is the default file name.
parseSource :: String -> String -> ([Decl], [Diag])
parseSource file src = case lexSource file src of
  Left d -> ([], [d])
  Right toks -> case expandTemplates toks of
    Left d -> ([], [d])
    Right toks' -> parseTokens toks'
