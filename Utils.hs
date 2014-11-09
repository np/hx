{-# LANGUAGE OverloadedStrings, TypeSynonymInstances, FlexibleInstances #-}
module Utils where

import qualified Prelude as Prelude
import Prelude hiding (interact, putStr)
import Control.Monad (unless)
import Data.Binary
import Data.Char (isSpace,isDigit,toLower)
import Data.Functor ((<$>))
import Data.Monoid
import Data.String
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LB8
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import Network.Haskoin.Crypto
import Network.Haskoin.Internals (FieldP, FieldN, getBigWordInteger, Point, curveN)
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
    where (s',rest) = B16.decode (ignoreSpacesBS s)

instance Hex LBS.ByteString where
  decodeHex msg = decodeHex msg . toStrictBS
  encodeHex     = toLazyBS . encodeHex

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

instance Interact LBS.ByteString where
  interact = LBS.interact

putLn :: (IsString s, Monoid s) => s -> s
putLn = (<> "\n")

showB8 :: Show a => a -> BS
showB8 = B8.pack . show

strictReadDigits :: Read a => String -> String -> a
strictReadDigits  msg s | all isDigit s = read s
                  | otherwise     = error $ "Invalid number containing non digits (while reading " <> msg <> ")"

-- Same as strictReadDigits but ignore spaces in the input
readDigits :: Read a => String -> String -> a
readDigits  msg = strictReadDigits msg . ignoreSpacesS

parseInt    :: String -> String -> Int
parseWord8  :: String -> String -> Word8
parseWord32 :: String -> String -> Word32
parseWord64 :: String -> String -> Word64

parseInt    = readDigits
parseWord8  = readDigits
parseWord32 = readDigits
parseWord64 = readDigits

show01 :: IsString s => Bool -> s
show01 True  = "1"
show01 False = "0"

read01 :: String -> Bool
read01 s
  | map toLower s `elem` ["0","false","no"] = False
  | map toLower s `elem` ["1","true","yes"] = True
  | otherwise = error $ "Expect 0, false, no, 1, true, or yes, not " ++ show s

ignoreSpacesS :: String -> String
ignoreSpacesS = filter $ not . isSpace

ignoreSpacesBS :: BS -> BS
ignoreSpacesBS = B8.filter $ not . isSpace

interactLn :: (IsString s, Monoid s, Interact s) => (s -> s) -> IO ()
interactLn f = interact $ putLn . f

putHex :: (Hex s, Binary a) => a -> s
putHex = encodeHex . encode'

getHex :: (Hex s, Binary a) => String -> s -> a
getHex msg = decode' . decodeHex msg

withHex :: (Hex s, Hex s', Monoid s', IsString s') => (BS -> BS) -> s -> s'
withHex f = putLn . encodeHex . f . decodeHex "input"

-- Non DER
getFieldN :: Get FieldN
getFieldN = do
  i <- getBigWordInteger <$> (get :: Get Word256)
  unless (i < curveN) (fail $ "Get: Integer not in FieldN: " ++ show i)
  return $ fromInteger i

-- Non DER
putFieldN :: FieldN -> Put
putFieldN = (put :: Word256 -> Put) . fromIntegral

getHexN :: Hex s => s -> FieldN
getHexN = runGet' getFieldN . decodeHex "field number modulo N"

putHexN :: Hex s => FieldN -> s
putHexN = encodeHex . runPut' . putFieldN

getHexP :: Hex s => s -> FieldP
getHexP = getHex "field number modulo P"

putHexP :: Hex s => FieldP -> s
putHexP = putHex

putHex256 :: Hex s => Word256 -> s
putHex256 = putHex

-- Little endian version of getHex
getHexLE :: (Binary a, Hex s) => String -> s -> a
getHexLE msg = decode' . BS.reverse . decodeHex (msg ++ " (little endian)")

getPoint :: Hex s => s -> Point
getPoint = pubKeyPoint . getHex "curve point"

putPoint :: Hex s => Point -> s
putPoint = putHex . PubKey

interactHex :: (BS -> BS) -> IO ()
interactHex f = interact (withHex f :: BS -> BS)

interactArgs :: (Interact s, PutStr s, IsString s, Eq s) => ([s] -> s) -> [s] -> IO ()
interactArgs f [] = interact (f . return)
interactArgs f xs = case length (filter (=="-") xs) of
  0 -> putStr (f xs)
  1 -> interact (\s -> f $ map (subst ("-", s)) xs)
  n -> error $ "Using '-' to read from standard input can be used only once, not " ++ show n ++ " times."

interactArgsLn :: (Interact s, PutStr s, IsString s, Eq s, Monoid s) => ([s] -> s) -> [s] -> IO ()
interactArgsLn f xs = interactArgs (putLn . f) xs

splitOn :: Char -> String -> (String, String)
splitOn c xs = (ys, tail zs)
  where (ys,zs) = span (/= c) xs

decodeHexBytes :: Hex s => String -> Int -> s -> BS
decodeHexBytes msg b s
  | l == b    = x
  | otherwise = error . unwords $ ["invalid", msg, "(should be"
                                  ,show (8 * b), "bits and not"
                                  ,show (8 * l), "bits)"]
  where x = decodeHex msg s
        l = BS.length x
