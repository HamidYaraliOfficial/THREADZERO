-- | Controlled token-level template expansion:
--     template Name(p1, p2) { ...tokens... }
--     apply Name(arg1, arg2);
--   Bounded depth and total size; no recursion beyond 8 levels.
module TZ.Template (expandTemplates) where

import qualified Data.Map.Strict as M
import TZ.Lexer
import TZ.Types

type Defs = M.Map String ([String], [Token])

expandTemplates :: [Token] -> Either Diag [Token]
expandTemplates ts = do
  (defs, rest) <- collect M.empty [] ts
  out <- expandAll defs (0 :: Int) rest
  if length out > 200000
    then Left (mkDiag SevError "TZ1105" (tkPos (head ts)) "template expansion produced too many tokens (limit 200000)")
    else Right out

bad :: Pos -> String -> String -> Either Diag a
bad p c m = Left (mkDiag SevError c p m)

collect :: Defs -> [Token] -> [Token] -> Either Diag (Defs, [Token])
collect defs acc ts = case ts of
  [] -> Right (defs, reverse acc)
  (Token p (TId "template") : rest) -> do
    (name, rest1) <- ident p rest
    rest2 <- expectSym p "(" rest1
    (params, rest3) <- params' p rest2 []
    rest4 <- expectSym p "{" rest3
    (body, rest5) <- block p 1 rest4 []
    collect (M.insert name (params, body) defs) acc rest5
  (t : rest) -> collect defs (t : acc) rest

ident :: Pos -> [Token] -> Either Diag (String, [Token])
ident _ (Token _ (TId n) : r) = Right (n, r)
ident p _ = bad p "TZ1101" "expected a template name"

expectSym :: Pos -> String -> [Token] -> Either Diag [Token]
expectSym _ s (Token _ (TSym x) : r) | x == s = Right r
expectSym p s _ = bad p "TZ1101" ("expected '" ++ s ++ "' in template declaration")

params' :: Pos -> [Token] -> [String] -> Either Diag ([String], [Token])
params' p ts acc = case ts of
  (Token _ (TSym ")") : r) -> Right (reverse acc, r)
  (Token _ (TSym ",") : r) -> params' p r acc
  (Token _ (TId n) : r) -> params' p r (n : acc)
  _ -> bad p "TZ1101" "malformed template parameter list"

block :: Pos -> Int -> [Token] -> [Token] -> Either Diag ([Token], [Token])
block p d ts acc = case ts of
  [] -> bad p "TZ1101" "unterminated template body"
  (Token _ TEOF : _) -> bad p "TZ1101" "unterminated template body"
  (t@(Token _ (TSym "{")) : r) -> block p (d + 1) r (t : acc)
  (t@(Token _ (TSym "}")) : r)
    | d == 1 -> Right (reverse acc, r)
    | otherwise -> block p (d - 1) r (t : acc)
  (t : r) -> block p d r (t : acc)

expandAll :: Defs -> Int -> [Token] -> Either Diag [Token]
expandAll defs depth ts = go ts []
  where
    go [] acc = Right (concat (reverse acc))
    go (Token p (TId "apply") : rest) acc = do
      when' (depth >= 8) (bad p "TZ1104" "template expansion depth exceeded (limit 8)")
      (name, rest1) <- ident p rest
      rest2 <- expectSym p "(" rest1
      (args, rest3) <- splitArgs p rest2
      let rest4 = case rest3 of (Token _ (TSym ";") : r) -> r; r -> r
      case M.lookup name defs of
        Nothing -> bad p "TZ1102" ("unknown template '" ++ name ++ "'")
        Just (ps, body)
          | length ps /= length args ->
              bad p "TZ1103" ("template '" ++ name ++ "' expects " ++ show (length ps) ++ " argument(s) but got " ++ show (length args))
          | otherwise -> do
              let sub = M.fromList (zip ps args)
                  body' = concatMap (subst p sub) body
              inner <- expandAll defs (depth + 1) body'
              go rest4 (inner : acc)
    go (t : rest) acc = go rest ([t] : acc)

    when' c e = if c then e else Right ()

    subst p sub (Token _ (TId n)) | Just a <- M.lookup n sub = a
    subst p _ (Token _ t) = [Token p t]

splitArgs :: Pos -> [Token] -> Either Diag ([[Token]], [Token])
splitArgs p ts0 = loop (0 :: Int) ts0 [] []
  where
    loop d ts cur acc = case ts of
      [] -> bad p "TZ1101" "unterminated apply(...) argument list"
      (Token _ TEOF : _) -> bad p "TZ1101" "unterminated apply(...) argument list"
      (t@(Token _ (TSym s)) : r)
        | s == ")" && d == 0 -> Right (finish cur acc, r)
        | s == "," && d == 0 -> loop d r [] (reverse cur : acc)
        | s `elem` ["(", "[", "{"] -> loop (d + 1) r (t : cur) acc
        | s `elem` [")", "]", "}"] -> loop (d - 1) r (t : cur) acc
      (t : r) -> loop d r (t : cur) acc
    finish cur acc = reverse (if null cur && null acc then acc else reverse cur : acc)
