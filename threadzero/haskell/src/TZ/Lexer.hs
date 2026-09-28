-- | Hand-written lexer with exact line/column tracking.
--   Supports '#' and '//' comments and the '#@file <path>' pragma emitted by the
--   Python project loader so diagnostics point into the original imported file.
module TZ.Lexer (Tok(..), Token(..), lexSource, showTok) where

import Data.Char (isAlpha, isAlphaNum, isDigit)
import TZ.Types

data Tok
  = TId String | TStr String | TNum Int | TDur Int Char | TTime Int | TSym String | TEOF
  deriving (Eq, Show)

data Token = Token { tkPos :: Pos, tkTok :: Tok } deriving (Show)

showTok :: Tok -> String
showTok t = case t of
  TId s -> "'" ++ s ++ "'"
  TStr s -> show s
  TNum n -> show n
  TDur n u -> show n ++ [u]
  TTime m -> show (m `div` 60) ++ ":" ++ pad (m `mod` 60)
  TSym s -> "'" ++ s ++ "'"
  TEOF -> "end of input"
  where pad n = (if n < 10 then "0" else "") ++ show n

lexSource :: String -> String -> Either Diag [Token]
lexSource file0 src = go file0 1 1 src []
  where
    err f l c m = Left (mkDiag SevError "TZ1001" (Pos f l c) m)

    go f l c s acc = case s of
      [] -> Right (reverse (Token (Pos f l c) TEOF : acc))
      ('#' : '@' : rest)
        | take 5 rest == "file " ->
            let (name, rest') = break (== '\n') (drop 5 rest)
            in go (trim name) 0 1 rest' acc
      ('\n' : r) -> go f (l + 1) 1 r acc
      (ch : r) | ch `elem` " \t\r" -> go f l (c + 1) r acc
      ('#' : _) -> go f l c (dropWhile (/= '\n') s) acc
      ('/' : '/' : _) -> go f l c (dropWhile (/= '\n') s) acc
      ('"' : r) -> string f l c r [] (c + 1) acc
      (ch : _)
        | isDigit ch -> number f l c s acc
        | isAlpha ch || ch == '_' ->
            let (w, r) = span (\x -> isAlphaNum x || x == '_') s
            in go f l (c + length w) r (Token (Pos f l c) (TId w) : acc)
      (a : b : r)
        | [a, b] `elem` ["==", "!=", ">=", "<=", "->", "=>", "&&", "||"] ->
            go f l (c + 2) r (Token (Pos f l c) (TSym [a, b]) : acc)
        | otherwise -> single f l c s acc
      _ -> single f l c s acc

    single f l c (ch : r) acc
      | ch `elem` "{}()[],;:.<>*@!" = go f l (c + 1) r (Token (Pos f l c) (TSym [ch]) : acc)
      | otherwise = err f l c ("unexpected character " ++ show ch)
    single f l c [] acc = go f l c [] acc

    string f l c0 r buf c acc = case r of
      [] -> err f l c0 "unterminated string literal"
      ('\n' : _) -> err f l c0 "unterminated string literal (strings cannot span lines)"
      ('"' : r') -> go f l (c + 1) r' (Token (Pos f l c0) (TStr (reverse buf)) : acc)
      ('\\' : e : r') ->
        let ch = case e of 'n' -> '\n'; 't' -> '\t'; 'r' -> '\r'; x -> x
        in string f l c0 r' (ch : buf) (c + 2) acc
      (ch : r') -> string f l c0 r' (ch : buf) (c + 1) acc

    number f l c s acc =
      let (ds, r) = span isDigit s
          n = read ds :: Int
          w = length ds
      in case r of
           (':' : d1 : d2 : r') | isDigit d1 && isDigit d2 ->
             let hh = n; mm = read [d1, d2] :: Int
             in if hh > 24 || mm > 59 || (hh == 24 && mm > 0)
                  then err f l c "invalid time literal (expected HH:MM between 00:00 and 24:00)"
                  else go f l (c + w + 3) r' (Token (Pos f l c) (TTime (hh * 60 + mm)) : acc)
           (u : r') | u `elem` "smhdwy" && not (startsIdent r') ->
             go f l (c + w + 1) r' (Token (Pos f l c) (TDur n u) : acc)
           _ -> go f l (c + w) r (Token (Pos f l c) (TNum n) : acc)

    startsIdent (x : _) = isAlphaNum x || x == '_'
    startsIdent [] = False

    trim = reverse . dropWhile (`elem` " \r") . reverse . dropWhile (== ' ')
