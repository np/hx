{-# LANGUAGE OverloadedStrings, TypeSynonymInstances, FlexibleInstances #-}
module Utils where

import Control.Applicative
import Data.Binary
import Data.Char (isSpace,isDigit,toLower)
import Data.Maybe
import Data.Monoid
import Data.String
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import Network.Haskoin.Crypto
import Network.Haskoin.Internals (FieldP, FieldN, getBigWordInteger, Point, curveN, curveP)
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

instance Hex LBS.ByteString where
  decodeHex msg = decodeHex msg . toStrictBS
  encodeHex     = toLazyBS . encodeHex

putLn :: (IsString s, Monoid s) => s -> s
putLn = (<> "\n")

showB8 :: Show a => a -> BS
showB8 = B8.pack . show

strictReadDigits :: Read a => String -> BS -> a
strictReadDigits msg s
  | B8.all isDigit s = read (B8.unpack s)
  | otherwise        = error $ "Invalid number containing non digits (while reading " <> msg <> ")"

-- Same as strictReadDigits but ignore spaces in the input
readDigits :: Read a => String -> BS -> a
readDigits  msg = strictReadDigits msg . ignoreSpaces

parseInt    :: String -> BS -> Int
parseWord8  :: String -> BS -> Word8
parseWord32 :: String -> BS -> Word32
parseWord64 :: String -> BS -> Word64

parseInt    = readDigits
parseWord8  = readDigits
parseWord32 = readDigits
parseWord64 = readDigits

readBS :: Read a => BS -> a
readBS = read . B8.unpack

show01 :: IsString s => Bool -> s
show01 True  = "1"
show01 False = "0"

read01 :: BS -> Bool
read01 s
  | B8.map toLower s `elem` ["0","false","no"] = False
  | B8.map toLower s `elem` ["1","true","yes"] = True
  | otherwise = error $ "Expect 0, false, no, 1, true, or yes, not " ++ show s

ignoreSpaces :: BS -> BS
ignoreSpaces = B8.filter $ not . isSpace

interactLn :: (BS -> BS) -> IO ()
interactLn f = BS.interact $ putLn . f

putHex :: (Hex s, Binary a) => a -> s
putHex = encodeHex . encode'

getHex :: (Hex s, Binary a) => String -> s -> a
getHex msg = decode' . decodeHex msg

withHex :: (Hex s, Hex s', Monoid s', IsString s') => (BS -> BS) -> s -> s'
withHex f = putLn . encodeHex . f . decodeHex "input"

integerN :: Integer -> FieldN
integerN i | i < curveN = fromInteger i
           | otherwise  = error $ "Integer not in FieldN: " ++ show i

integerP :: Integer -> FieldP
integerP i | i < curveP = fromInteger i
           | otherwise  = error $ "Integer not in FieldP: " ++ show i

-- Non DER
getFieldN :: Get FieldN
getFieldN = integerN . getBigWordInteger <$> (get :: Get Word256)

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

getDecModN :: BS -> FieldN
getDecModN = fromInteger . readDigits "integer modulo n in decimal"

getDecModP :: BS -> FieldP
getDecModP = fromInteger . readDigits "integer modulo p in decimal"

getDecStrictN :: BS -> FieldN
getDecStrictN = integerN . readDigits "integer modulo n in decimal"

getDecStrictP :: BS -> FieldP
getDecStrictP = integerP . readDigits "integer modulo p in decimal"


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
interactHex f = BS.interact (withHex f :: BS -> BS)

interactArgs' :: (IsString s, Eq s) => (s -> IO ()) -> IO s -> ([s] -> s) -> [s] -> IO ()
interactArgs' puts gets f [] = puts . f . return =<< gets
interactArgs' puts gets f xs = case length (filter (=="-") xs) of
  0 -> puts (f xs)
  1 -> gets >>= (\s -> puts . f $ map (subst ("-", s)) xs)
  n -> error $ "Using '-' to read from standard input can be used only once, not " ++ show n ++ " times."

interactArgs :: ([BS] -> BS) -> [BS] -> IO ()
interactArgs = interactArgs' BS.putStr BS.getContents

interactArgsLn :: ([BS] -> BS) -> [BS] -> IO ()
interactArgsLn = interactArgs . (putLn .)

interactArg :: String -> (BS -> BS) -> [BS] -> IO ()
interactArg msg f = interactArgs f'
  where f' [x] = f x
        f' _   = error $ "Too many arguments.\nUsage: " ++ msg

interactArgLn :: String -> (BS -> BS) -> [BS] -> IO ()
interactArgLn msg = interactArg msg . (putLn .)

writeArg :: BS -> BS -> IO ()
writeArg "-" = BS.putStr
writeArg fp  = BS.writeFile (B8.unpack fp)

interactFileArgs :: ([BS] -> BS) -> BS -> [BS] -> IO ()
interactFileArgs f file = interactArgs' (writeArg file) BS.getContents f

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

makePrvKey256 :: BS -> PrvKey
makePrvKey256 s
  | BS.length s == 32 = fromMaybe (error "makePrvKey256: invalid key") . makePrvKey $ bsToInteger s
  | otherwise         = error $ "makePrvKey256: invalid size for input key, should be 256 bits and not " ++ show (BS.length s * 8) ++ " bits"

makePrvKeyU256 :: BS -> PrvKey
makePrvKeyU256 s
  | BS.length s == 32 = fromMaybe (error "makePrvKeyU256: invalid key") . makePrvKeyU $ bsToInteger s
  | otherwise         = error $ "makePrvKeyU256: invalid size for input key, should be 256 bits and not " ++ show (BS.length s * 8) ++ " bits"
