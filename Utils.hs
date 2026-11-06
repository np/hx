{-# LANGUAGE OverloadedStrings #-}

module Utils where

import Control.Exception (evaluate)
import Crypto.Hash (Digest, HashAlgorithm, hashWith)
import Crypto.Hash.Algorithms (RIPEMD160 (..), SHA1 (..), SHA224 (..), SHA256 (..), SHA384 (..), SHA512 (..))
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (Serial (..))
import Data.Char (isDigit, isHexDigit, isSpace, toLower)
import Data.String (IsString)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word32, Word64, Word8)
import qualified Haskoin.Util as H
import Output (Out (..))

type BS = BS.ByteString

subst :: (Eq a) => (a, a) -> a -> a
subst (x, y) z
  | x == z = y
  | otherwise = z

-- * Hexadecimal

-- | Decode hexadecimal, ignoring white space. The first argument names the
-- decoded value in the error message.
decodeHex :: String -> BS -> BS
decodeHex msg s =
  case H.decodeHex (TE.decodeLatin1 (ignoreSpaces s)) of
    Just r -> r
    Nothing -> error $ msg ++ ": invalid hex encoding"

encodeHex :: BS -> BS
encodeHex = TE.encodeUtf8 . H.encodeHex

isHex :: String -> Bool
isHex = all (\c -> isHexDigit c || isSpace c)

-- | Decode hexadecimal of a fixed number of bytes.
decodeHexBytes :: String -> Int -> BS -> BS
decodeHexBytes msg b s
  | l == b = x
  | otherwise =
      error . unwords $
        [ "invalid",
          msg,
          "(should be",
          show (8 * b),
          "bits and not",
          show (8 * l),
          "bits)"
        ]
  where
    x = decodeHex msg s
    l = BS.length x

-- * Binary serialization

encodeS :: (Serial a) => a -> BS
encodeS = runPutS . serialize

decodeS :: (Serial a) => String -> BS -> a
decodeS msg = either (\e -> error $ "invalid " ++ msg ++ ": " ++ e) id . runGetS deserialize

putHex :: (Serial a) => a -> BS
putHex = encodeHex . encodeS

getHex :: (Serial a) => String -> BS -> a
getHex msg = decodeS msg . decodeHex msg

-- | Little endian version of getHex (for transaction hashes as displayed).
getHexLE :: (Serial a) => String -> BS -> a
getHexLE msg = decodeS msg . BS.reverse . decodeHex (msg ++ " (little endian)")

-- * Text

toText :: BS -> T.Text
toText = TE.decodeUtf8

fromText :: T.Text -> BS
fromText = TE.encodeUtf8

showB8 :: (Show a) => a -> BS
showB8 = B8.pack . show

ignoreSpaces :: BS -> BS
ignoreSpaces = B8.filter $ not . isSpace

trim :: BS -> BS
trim = B8.dropWhile isSpace . B8.dropWhileEnd isSpace

-- * Numbers

strictReadDigits :: (Read a) => String -> BS -> a
strictReadDigits msg s
  | not (BS.null s) && B8.all isDigit s = read (B8.unpack s)
  | otherwise = error $ "Invalid number containing non digits (while reading " <> msg <> ")"

-- | Same as strictReadDigits but ignore spaces in the input
readDigits :: (Read a) => String -> BS -> a
readDigits msg = strictReadDigits msg . ignoreSpaces

-- | Read a non-negative number and check it fits in the target type.
readBounded :: forall a. (Integral a, Bounded a) => String -> BS -> a
readBounded msg s
  | i <= toInteger (maxBound :: a) = fromInteger i
  | otherwise = error $ "Number too large (while reading " <> msg <> ")"
  where
    i = readDigits msg s :: Integer

parseInt :: String -> BS -> Int
parseInt = readBounded

parseWord8 :: String -> BS -> Word8
parseWord8 = readBounded

parseWord32 :: String -> BS -> Word32
parseWord32 = readBounded

parseWord64 :: String -> BS -> Word64
parseWord64 = readBounded

readBS :: (Read a) => BS -> a
readBS = read . B8.unpack

show01 :: (IsString s) => Bool -> s
show01 True = "1"
show01 False = "0"

read01 :: BS -> Bool
read01 s
  | B8.map toLower s `elem` ["0", "false", "no"] = False
  | B8.map toLower s `elem` ["1", "true", "yes"] = True
  | otherwise = error $ "Expect 0, false, no, 1, true, or yes, not " ++ show s

-- * Argument handling

get_arg :: String -> String -> [BS] -> (BS, [BS])
get_arg n u [] = error . unwords $ ["Missing", n ++ ".\nUsage:", u]
get_arg _ _ (arg : args) = (arg, args)

get_hex_arg :: String -> String -> [BS] -> (BS, [BS])
get_hex_arg n u [] = error . unwords $ ["Missing", n ++ ".\nUsage:", u]
get_hex_arg n u ["--hex"] = error . unwords $ ["Missing", n ++ " in hexadecimal.\nUsage:", u]
get_hex_arg n _ ("--hex" : hex_arg : args) = (decodeHex n hex_arg, args)
get_hex_arg _ _ (arg : args) = (arg, args)

get_int_arg :: String -> String -> [BS] -> (Int, [BS])
get_int_arg n u [] = error . unwords $ ["Missing", n ++ ".\nUsage:", u]
get_int_arg n u (arg : args)
  | not (BS.null arg) && B8.all isDigit arg = (readBS arg, args)
  | otherwise = error . unwords $ ["Non-decimal digits for", n ++ ".\nUsage:", u]

no_args :: String -> [BS] -> a -> a
no_args _ [] x = x
no_args u _ _ = error $ "Too many arguments.\nUsage: " ++ u

-- | Extract @--flag VALUE@ options (in any position) from an argument list.
-- Returns the values of the given option and the remaining arguments.
takeOpt :: [BS] -> [BS] -> ([BS], [BS])
takeOpt names = go
  where
    go (o : v : rest)
      | o `elem` names = let (vs, r) = go rest in (v : vs, r)
    go [o]
      | o `elem` names = error $ "Missing value for option " ++ B8.unpack o
    go (a : rest) = let (vs, r) = go rest in (vs, a : r)
    go [] = ([], [])

-- | Like 'takeOpt' for an option given at most once.
takeOpt1 :: [BS] -> [BS] -> (Maybe BS, [BS])
takeOpt1 names args = case takeOpt names args of
  ([], r) -> (Nothing, r)
  ([v], r) -> (Just v, r)
  _ -> error $ "Option given more than once: " ++ B8.unpack (B8.unwords names)

-- | Extract boolean @--flag@ switches from an argument list.
takeFlag :: [BS] -> [BS] -> (Bool, [BS])
takeFlag names args = (any (`elem` names) args, filter (`notElem` names) args)

-- * Interaction with standard input and output

-- | Apply a function to standard input and print its result.
interactLn :: (Out o) => (BS -> o) -> IO ()
interactLn f = emit . f =<< BS.getContents

-- | Apply a function to the arguments, where a single '-' argument (or no
-- argument at all) stands for standard input.
interactArgs' :: ([BS] -> o) -> (o -> IO ()) -> [BS] -> IO ()
interactArgs' f puts [] = puts . f . pure =<< BS.getContents
interactArgs' f puts xs = case length (filter (== "-") xs) of
  0 -> puts (f xs)
  1 -> BS.getContents >>= (\s -> puts . f $ map (subst ("-", s)) xs)
  n -> error $ "Using '-' to read from standard input can be used only once, not " ++ show n ++ " times."

interactArgs :: (Out o) => ([BS] -> o) -> [BS] -> IO ()
interactArgs f = interactArgs' f emit

-- | Like 'interactArgs' for commands taking exactly one argument.
interactArg :: (Out o) => String -> (BS -> o) -> [BS] -> IO ()
interactArg msg f = interactArgs f'
  where
    f' [x] = f x
    f' _ = error $ "Too many arguments.\nUsage: " ++ msg

-- | Read one hexadecimal argument (or standard input) and print the result
-- of the function in hexadecimal.
interactHex :: String -> (BS -> BS) -> [BS] -> IO ()
interactHex msg f = interactArg msg (withHex f)

withHex :: (BS -> BS) -> BS -> BS
withHex f = encodeHex . f . decodeHex "input"

-- | Write a raw result to a file, or print it when the file is '-'.
interactFileArgs :: ([BS] -> BS) -> BS -> [BS] -> IO ()
interactFileArgs f "-" = interactArgs' f emit
interactFileArgs f file = interactArgs' f $ \r -> do
  _ <- evaluate (BS.length r)
  BS.writeFile (B8.unpack file) r

splitOnBS :: Char -> BS -> (BS, BS)
splitOnBS c s =
  case B8.span (/= c) s of
    (s1, s2) -> (s1, BS.drop 1 s2)

-- * Hash functions on raw bytes

digestBS :: forall a. (HashAlgorithm a) => a -> BS -> BS
digestBS a bs = BA.convert (hashWith a bs :: Digest a)

sha1BS, sha224BS, sha256BS, sha384BS, sha512BS, ripemd160BS :: BS -> BS
sha1BS = digestBS SHA1
sha224BS = digestBS SHA224
sha256BS = digestBS SHA256
sha384BS = digestBS SHA384
sha512BS = digestBS SHA512
ripemd160BS = digestBS RIPEMD160

-- | RIPEMD160 of SHA256
hash160BS :: BS -> BS
hash160BS = ripemd160BS . sha256BS

-- | Double SHA256
hash256BS :: BS -> BS
hash256BS = sha256BS . sha256BS

-- | First four bytes of the double SHA256
chksum32BS :: BS -> BS
chksum32BS = BS.take 4 . hash256BS

-- | BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
taggedHashBS :: BS -> BS -> BS
taggedHashBS tag msg = sha256BS (t <> t <> msg)
  where
    t = sha256BS tag
