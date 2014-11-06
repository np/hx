{-# LANGUAGE OverloadedStrings, TypeSynonymInstances, FlexibleInstances #-}
module Utils where

import qualified Prelude as Prelude
import Prelude hiding (interact, filter)
import Data.String
import Data.Monoid
import Data.Binary
import Data.Char (isSpace)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import Network.Haskoin.Util

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
    where (s',rest) = B16.decode s

class Filter s where
  filter :: (Char -> Bool) -> s -> s

instance Filter String where
  filter = Prelude.filter

instance Filter BS where
  filter = B8.filter

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

-- | Ignoring the spaces in the input, hence the function receives a single
--   word.
interactOneWord :: (IsString s, Monoid s, Filter s, Interact s) => (s -> s) -> IO ()
interactOneWord f = interact $ putLn . f . ignoreSpaces

putHex :: (Hex s, Binary a) => a -> s
putHex = encodeHex . encode'

getHex :: (Hex s, Binary a) => String -> s -> a
getHex msg = decode' . decodeHex msg

withHex :: (Hex s, Hex s') => (BS -> BS) -> s -> s'
withHex f = encodeHex . f . decodeHex "input"

interactHex :: (BS -> BS) -> IO ()
interactHex f = interactOneWord (withHex f :: BS -> BS)

splitOn :: Char -> String -> (String, String)
splitOn c xs = (ys, tail zs)
  where (ys,zs) = span (/= c) xs
