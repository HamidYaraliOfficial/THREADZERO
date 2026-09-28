-- | Minimal JSON value + renderer (no external dependencies).
module TZ.Json
  ( J(..), render, str, strs, ints, obj, arr, jbool, jint, jmaybe, jnum
  ) where

import Data.Char (ord)
import Numeric (showHex)

data J
  = JNull
  | JBool Bool
  | JInt Int
  | JNum Double
  | JStr String
  | JArr [J]
  | JObj [(String, J)]
  deriving (Eq, Show)

str :: String -> J
str = JStr

strs :: [String] -> J
strs = JArr . map JStr

ints :: [Int] -> J
ints = JArr . map JInt

obj :: [(String, J)] -> J
obj = JObj

arr :: [J] -> J
arr = JArr

jbool :: Bool -> J
jbool = JBool

jint :: Int -> J
jint = JInt

jnum :: Double -> J
jnum = JNum

jmaybe :: (a -> J) -> Maybe a -> J
jmaybe = maybe JNull

render :: J -> String
render j = go j ""
  where
    go :: J -> ShowS
    go JNull = showString "null"
    go (JBool b) = showString (if b then "true" else "false")
    go (JInt n) = shows n
    go (JNum d) = showString (fmt d)
    go (JStr s) = quote s
    go (JArr xs) = showChar '[' . commaSep (map go xs) . showChar ']'
    go (JObj kvs) = showChar '{' . commaSep [quote k . showChar ':' . go v | (k, v) <- kvs] . showChar '}'

    fmt :: Double -> String
    fmt d = let r = fromIntegral (round (d * 1000) :: Integer) / 1000 :: Double in show r

    commaSep :: [ShowS] -> ShowS
    commaSep [] = id
    commaSep [x] = x
    commaSep (x : xs) = x . showChar ',' . commaSep xs

    quote :: String -> ShowS
    quote s = showChar '"' . foldr (\c k -> esc c . k) id s . showChar '"'

    esc :: Char -> ShowS
    esc '"' = showString "\\\""
    esc '\\' = showString "\\\\"
    esc '\n' = showString "\\n"
    esc '\r' = showString "\\r"
    esc '\t' = showString "\\t"
    esc c
      | ord c < 0x20 = showString "\\u" . showString (pad4 (showHex (ord c) ""))
      | otherwise = showChar c

    pad4 s = replicate (4 - length s) '0' ++ s
