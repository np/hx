{-# LANGUAGE OverloadedStrings, TypeSynonymInstances, FlexibleInstances #-}
module Utils where

import qualified Prelude as Prelude
import Prelude hiding (interact, filter, putStr)
import Data.String
import Data.Monoid
import Data.Binary
import Data.Char (isSpace)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LB8
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import Network.Haskoin.Util

subst :: Eq a => (a,a) -> a -> a
subst (x,y) z | x == z    = y
              | otherwise = z

type BS = BS.ByteString

class Hex s where
  -- | Decode a base16 (HEX) representation to a bytestring
  decodeHex :: String -> s -> BS

  -- | Encode a bytestring to a base16 (HEX) representation
  encodeHex :: BS -> s

instance Hex String where
  decodeHex msg = decodeHex msg . B8.pack
  encodeHex     = B8.unpack . encodeHex

instance Hex BS where
  encodeHex    = B16.encode
  decodeHex msg s
    | BS.null rest = s'
    | otherwise    = error $ msg ++ ": invalid hex encoding"
    where (s',rest) = B16.decode (ignoreSpaces s)

class Filter s where
  filter :: (Char -> Bool) -> s -> s

instance Filter String where
  filter = Prelude.filter

instance Filter BS where
  filter = B8.filter

class PutStr s where
  putStr   :: s -> IO ()
  putStrLn :: s -> IO ()

instance PutStr String where
  putStr   = Prelude.putStr
  putStrLn = Prelude.putStrLn

instance PutStr BS.ByteString where
  putStr   = BS.putStr
  putStrLn = B8.putStrLn

instance PutStr LBS.ByteString where
  putStr   = LBS.putStr
  putStrLn = LB8.putStrLn

class Interact s where
  interact :: (s -> s) -> IO ()

instance Interact String where
  interact = Prelude.interact

instance Interact BS.ByteString where
  interact = BS.interact

putLn :: (IsString s, Monoid s) => s -> s
putLn = (<> "\n")

ignoreSpaces :: Filter s => s -> s
ignoreSpaces  = filter $ not . isSpace

interactLn :: (IsString s, Monoid s, Interact s) => (s -> s) -> IO ()
interactLn f = interact $ putLn . f

putHex :: (Hex s, Binary a) => a -> s
putHex = encodeHex . encode'

getHex :: (Hex s, Binary a) => String -> s -> a
getHex msg = decode' . decodeHex msg

withHex :: (Hex s, Hex s', Monoid s', IsString s') => (BS -> BS) -> s -> s'
withHex f = putLn . encodeHex . f . decodeHex "input"

interactHex :: (BS -> BS) -> IO ()
interactHex f = interact (withHex f :: BS -> BS)

interactArgs :: (Interact s, PutStr s, IsString s, Eq s) => ([s] -> s) -> [s] -> IO ()
interactArgs f xs
  | "-" `elem` xs = interact (\s -> f $ map (subst ("-", s)) xs)
  | otherwise     = putStr (f xs)

interactArgsLn :: (Interact s, PutStr s, IsString s, Eq s, Monoid s) => ([s] -> s) -> [s] -> IO ()
interactArgsLn f xs = interactArgs (putLn . f) xs

splitOn :: Char -> String -> (String, String)
splitOn c xs = (ys, tail zs)
  where (ys,zs) = span (/= c) xs
