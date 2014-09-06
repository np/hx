{-# LANGUAGE OverloadedStrings, TypeSynonymInstances, FlexibleInstances #-}
import qualified Prelude as Prelude
import Prelude hiding (interact, filter)
import Data.Maybe
import Data.Either (partitionEithers)
import Data.Word
import Data.String
import Data.Monoid
import Data.Scientific
import Data.Binary
import Data.Functor ((<$>))
import Data.Char (isDigit,isSpace)
import Data.List (isPrefixOf)
import qualified Data.RFC1751 as RFC1751
import System.Environment
import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16

import Network.Haskoin.Crypto
import Network.Haskoin.Internals (FieldP, FieldN, BigWord(BigWord), Point
                                 , curveP, curveN, curveG, integerA, integerB
                                 , getX, getY, addPoint, doublePoint, mulPoint
                                 , OutPoint(OutPoint), Tx, Script
                                 , SigHash(SigAll), TxSignature(TxSignature)
                                 , txIn, scriptInput
                                 , buildAddrTx, txSigHash, encodeSig, decodeSig
                                 , getOutputAddress, decodeOutput
                                 , fromMnemonic
                                 )
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

interactOneWord :: (IsString s, Monoid s, Filter s, Interact s) => (s -> s) -> IO ()
interactOneWord f = interact $ putLn . f . ignoreSpaces

putHex :: (Hex s, Binary a) => a -> s
putHex = encodeHex . encode'

getHex :: (Hex s, Binary a) => String -> s -> a
getHex msg = runGet' get . decodeHex msg

interactHex :: (BS -> BS) -> IO ()
interactHex f = BS.interact $ putLn . encodeHex . f
                            . decodeHex "input" . ignoreSpaces

readTxFile :: FilePath -> IO Tx
readTxFile file = getHex "transaction" . ignoreSpaces <$> BS.readFile file

one_btc_in_satoshi :: Num a => a
one_btc_in_satoshi = 10^(8 :: Int)

-- Non DER
getFieldN :: Get FieldN
getFieldN = do
  (BigWord i) <- get :: Get Word256
  unless (i < curveN) (fail $ "Get: Integer not in FieldN: " ++ show i)
  return $ fromInteger i

decodeBase58E :: BS -> BS
decodeBase58E = fromMaybe (error "invalid base58 encoding") . decodeBase58

xPrvImportE :: String -> XPrvKey
xPrvImportE = fromMaybe (error "invalid extended private key") . xPrvImport

xPubImportE :: String -> XPubKey
xPubImportE = fromMaybe (error "invalid extended public key") . xPubImport

xMasterImportE :: Hex s => s -> XPrvKey
xMasterImportE = fromMaybe (error "failed to derived private root key from seed") . makeXPrvKey
               . decodeHex "seed"

xPrvExportC :: Char -> XPrvKey -> String
xPrvExportC 'A' = addrToBase58 . xPubAddr . deriveXPubKey
xPrvExportC 'M' = xPubExport . deriveXPubKey
xPrvExportC 'm' = xPrvExport
xPrvExportC  c  = error $ "Root path expected to be either m/ or M/ not " ++ c : "/"

xPubExportC :: Char -> XPubKey -> String
xPubExportC 'A' = addrToBase58 . xPubAddr
xPubExportC 'M' = xPubExport
xPubExportC 'm' = error "Private keys can not be derived from public keys (expected M/ not m/)"
xPubExportC  c  = error $ "Root path expected to be M/ not " ++ c : "/"

derivePrvPath :: String -> XPrvKey -> XPrvKey
derivePrvPath []       = id
derivePrvPath ('/':xs) = goIndex $ span isDigit xs
  where
  goIndex ([], _)       = error "derivePrvPath: empty path segment"
  goIndex (ys, '\'':zs) = derivePrvPath zs . flip primeSubKeyE (read ys)
  goIndex (ys, zs)      = derivePrvPath zs . flip prvSubKeyE   (read ys)
derivePrvPath _ = error "malformed path"

derivePubPath :: String -> XPubKey -> XPubKey
derivePubPath []       = id
derivePubPath ('/':xs) = goIndex $ span isDigit xs
  where
  goIndex ([], _)     = error "derivePubPath: empty path segment"
  goIndex (_, '\'':_) = error "derivePubPath: hardened subkeys are inaccessible from extended public keys"
  goIndex (ys, zs)    = derivePubPath zs . flip pubSubKeyE (read ys)
derivePubPath _ = error "malformed path"

fromWIFE :: String -> PrvKey
fromWIFE = fromMaybe (error "invalid WIF private key") . fromWIF

base58ToAddrE :: String -> Address
base58ToAddrE = fromMaybe (error "invalid bitcoin address") . base58ToAddr

prvSubKeyE :: XPrvKey -> Word32 -> XPrvKey
prvSubKeyE k = fromMaybe (error "failed to derive private sub key") . prvSubKey k

primeSubKeyE :: XPrvKey -> Word32 -> XPrvKey
primeSubKeyE k = fromMaybe (error "failed to derive private prime sub key") . primeSubKey k

pubSubKeyE :: XPubKey -> Word32 -> XPubKey
pubSubKeyE k = fromMaybe (error "failed to derive public sub key") . pubSubKey k

splitOn :: Char -> String -> (String, String)
splitOn c xs = (ys, tail zs)
  where (ys,zs) = span (/= c) xs

readOutPoint :: String -> OutPoint
readOutPoint xs = OutPoint (getHexLE "transaction hash" ys) (read zs) where (ys,zs) = splitOn ':' xs

readOutput :: String -> (String,Word64)
readOutput xs = (ys, read zs) where (ys,zs) = splitOn ':' xs

mktx_args :: [String] -> [Either OutPoint (String,Word64)]
mktx_args [] = []
mktx_args ( "--input":input :args) = Left (readOutPoint input) : mktx_args args
mktx_args (      "-i":input :args) = Left (readOutPoint input) : mktx_args args
mktx_args ("--output":output:args) = Right (readOutput output) : mktx_args args
mktx_args (      "-o":output:args) = Right (readOutput output) : mktx_args args
mktx_args _ = error "mktx_args: unexpected argument"

putTxSig :: Hex s => TxSignature -> s
putTxSig = encodeHex . encodeSig

getTxSig :: Hex s => s -> TxSignature
getTxSig = either error id . decodeSig . decodeHex "transaction signature"

hx_mktx :: Hex s => [String] -> s
hx_mktx args = putHex . either error id . uncurry buildAddrTx
             . partitionEithers $ mktx_args args

hx_pubkey :: Hex s => String -> s
hx_pubkey = putHex . derivePubKey . fromWIFE

hx_addr :: Hex s => s -> String
hx_addr = addrToBase58 . pubKeyAddr . decode' . decodeHex "address"

hx_wif_to_secret :: Hex s => String -> s
hx_wif_to_secret = encodeHex . runPut' . putPrvKey . fromWIFE

hx_secret_to_wif :: String -> String
hx_secret_to_wif = toWIF
                 . fromMaybe (error "invalid private key") . makePrvKey
                 . bsToInteger . decodeHex "private key"

hx_hd_to_wif :: String -> String
hx_hd_to_wif = xPrvWIF . xPrvImportE

-- TODO support private keys as well
hx_hd_to_address :: String -> String
hx_hd_to_address = addrToBase58 . xPubAddr . xPubImportE

hx_hd_to_pubkey :: Hex s => String -> s
hx_hd_to_pubkey = putHex . xPubKey . xPubImportE

hx_hd_priv :: Maybe (XPrvKey -> Word32 -> XPrvKey, Word32) -> String -> String
hx_hd_priv Nothing         = xPrvExport . xMasterImportE
hx_hd_priv (Just (sub, i)) = xPrvExport . flip sub i . xPrvImportE

hx_hd_pub :: Maybe Word32 -> String -> String
hx_hd_pub Nothing  = xPubExport . deriveXPubKey     . xPrvImportE
hx_hd_pub (Just i) = xPubExport . flip pubSubKeyE i . xPubImportE

hx_hd_path :: String -> String -> String
hx_hd_path []    _ = error "Empty path"
hx_hd_path (m:p) i
  | "xpub" `isPrefixOf` i = xPubExportC m . derivePubPath p $ xPubImportE    i
  | "xprv" `isPrefixOf` i = xPrvExportC m . derivePrvPath p $ xPrvImportE    i
  | otherwise             = xPrvExportC m . derivePrvPath p $ xMasterImportE i

hx_bip39_mnemonic :: Hex s => s -> String
hx_bip39_mnemonic = either error id . toMnemonic . decodeHex "seed"

hx_bip39_hex :: String -> String
hx_bip39_hex = putLn . bsToHex . either error id . fromMnemonic

hx_bip39_seed :: Passphrase -> Mnemonic -> String
hx_bip39_seed pf = putLn . bsToHex . either error id . mnemonicToSeed pf

hx_btc, hx_satoshi :: String -> String
hx_btc     = formatScientific Fixed (Just 8) . (/ one_btc_in_satoshi) . read
hx_satoshi = formatScientific Fixed (Just 0) . (* one_btc_in_satoshi) . read

hx_decode_addr :: String -> String
hx_decode_addr = bsToHex . encode' . getAddrHash . base58ToAddrE

hx_encode_addr :: Hex s => (Word160 -> Address) -> s -> String
hx_encode_addr f = addrToBase58 . f . getHex "address"

hx_base58_encode :: Hex s => s -> BS
hx_base58_encode = encodeBase58 . decodeHex "input"

hx_base58_decode :: Hex s => BS -> s
hx_base58_decode = encodeHex . decodeBase58E

hx_base58check_encode :: Hex s => s -> BS
hx_base58check_encode = encodeBase58Check . decodeHex "input"

hx_base58check_decode :: Hex s => BS -> s
hx_base58check_decode = encodeHex
                      . fromMaybe (error "invalid base58check encoding")
                      . decodeBase58Check

hx_rfc1751_key      :: (Monoid s, IsString s, Hex s) => BS -> s
hx_rfc1751_key      = putLn . encodeHex
                    . fromMaybe (error "invalid RFC1751 mnemonic") . RFC1751.mnemonicToKey
                    . B8.unpack

hx_rfc1751_mnemonic :: Hex s => s -> BS
hx_rfc1751_mnemonic = B8.pack
                    . fromMaybe (error "invalid RFC1751 128 bits key") . RFC1751.keyToMnemonic
                    . decodeHex "128 bits key"

-- set-input FILENAME N SIGNATURE_AND_PUBKEY_SCRIPT
hx_set_input :: FilePath -> String -> String -> IO ()
hx_set_input file index script =
  do tx <- readTxFile file
     B8.putStrLn . putHex $ hx_set_input' (read index) (decodeHex "script" script) tx

hx_set_input' :: Int -> BS.ByteString -> Tx -> Tx
hx_set_input' i si tx = tx{ txIn = updateIndex i (txIn tx) f }
  where f x = x{ scriptInput = si }

hx_validsig' :: Tx -> Int -> Script -> TxSignature -> PubKey -> Bool
hx_validsig' tx i out (TxSignature sig sh) pub =
  pubKeyAddr pub == a && verifySig (txSigHash tx out i sh) sig pub
  where a = getOutputAddress (either error id (decodeOutput out))

hx_validsig :: FilePath -> String -> String -> String -> IO ()
hx_validsig file i s sig =
  do tx <- readTxFile file
     interactOneWord $ putSuccess
                     . hx_validsig' tx (read i) (getHex "script" s) (getTxSig sig)
                     . getHex "public key"
  where putSuccess :: Bool -> BS
        putSuccess True = "Status: OK"
        putSuccess  _   = "Status: Failed"

hx_sign_input :: FilePath -> String -> String -> IO ()
hx_sign_input file index script_code =
  do tx <- readTxFile file
     interactOneWord $ putTxSig . hx_sign_input' tx (read index) (getHex "script" script_code) . fromWIFE

-- The pure and typed counter part of hx_sign_input
hx_sign_input' :: Tx -> Int -> Script -> PrvKey -> TxSignature
hx_sign_input' tx index script_output privkey = sig where
  sh  = SigAll False
  msg = txSigHash  tx script_output index sh
  sig = TxSignature (detSignMsg msg privkey) sh

-- TODO do something better than 'read' to parse the index
parseWord32 :: String -> Word32
parseWord32 = read

getHexN :: Hex s => s -> FieldN
getHexN = runGet' getFieldN . decodeHex "field number modulo N"

getHexP :: Hex s => s -> FieldP
getHexP = getHex "field number modulo P"

-- Little endian version of getHex
getHexLE :: (Binary a, Hex s) => String -> s -> a
getHexLE msg = runGet' get . BS.reverse . decodeHex (msg ++ " (little endian)")

getPoint :: Hex s => s -> Point
getPoint = pubKeyPoint . getHex "curve point"

putPoint :: Hex s => Point -> s
putPoint = putHex . PubKey

mainArgs :: [String] -> IO ()
mainArgs ["pubkey"]                  = interactOneWord hx_pubkey
mainArgs ["addr"]                    = interactOneWord hx_addr
mainArgs ["wif-to-secret"]           = interactOneWord hx_wif_to_secret
mainArgs ["secret-to-wif"]           = interactOneWord hx_secret_to_wif
mainArgs ["hd-priv"]                 = interactOneWord $ hx_hd_priv   Nothing
mainArgs ["hd-priv", i]              = interactOneWord . hx_hd_priv $ Just (prvSubKeyE,   parseWord32 i)
mainArgs ["hd-priv", "--hard", i]    = interactOneWord . hx_hd_priv $ Just (primeSubKeyE, parseWord32 i)
mainArgs ["hd-pub"]                  = interactOneWord $ hx_hd_pub    Nothing
mainArgs ["hd-pub", i]               = interactOneWord . hx_hd_pub  . Just $ parseWord32 i
mainArgs ["hd-path", p]              = interactOneWord $ hx_hd_path p
mainArgs ["hd-to-wif"]               = interactOneWord hx_hd_to_wif
mainArgs ["hd-to-pubkey"]            = interactOneWord hx_hd_to_pubkey
mainArgs ["hd-to-address"]           = interactOneWord hx_hd_to_address
mainArgs ["bip39-mnemonic"]          = interactOneWord hx_bip39_mnemonic
mainArgs ["bip39-hex"]               = interact hx_bip39_hex
mainArgs ["bip39-seed", pass]        = interact $ hx_bip39_seed pass
mainArgs ["base58-encode"]           = interactOneWord hx_base58_encode
mainArgs ["base58-decode"]           = interactOneWord hx_base58_decode
mainArgs ["base58check-encode"]      = interactOneWord hx_base58check_encode
mainArgs ["base58check-decode"]      = interactOneWord hx_base58check_decode
mainArgs ["encode-addr", "--script"] = interactOneWord $ hx_encode_addr ScriptAddress
mainArgs ["encode-addr"]             = interactOneWord $ hx_encode_addr PubKeyAddress
mainArgs ["decode-addr"]             = interactOneWord hx_decode_addr
mainArgs ["encode-hex"]              = interact encodeHex
mainArgs ["decode-hex"]              = interact $ decodeHex "input" . ignoreSpaces
mainArgs ["ripemd-hash"]             = interact $ encodeHex . hash160BS . hash256BS
mainArgs ["sha256"]                  = interactHex hash256BS
mainArgs ["ec-double", p]            = B8.putStrLn . putPoint . doublePoint $ getPoint p
mainArgs ["ec-add", p, q]            = B8.putStrLn . putPoint $ addPoint (getPoint p) (getPoint q)
mainArgs ["ec-multiply", x, p]       = B8.putStrLn . putPoint $ mulPoint (getHexN x) (getPoint p)
mainArgs ["ec-tweak-add", x, p]      = B8.putStrLn . putPoint $ addPoint (mulPoint (getHexN x) curveG) (getPoint p)
mainArgs ["ec-add-modp", x, y]       = B8.putStrLn $ putHex (getHexP x + getHexP y)
mainArgs ["ec-add-modn", x, y]       = B8.putStrLn $ putHex (getHexN x + getHexN y :: FieldN)
mainArgs ["ec-g"]                    = B8.putStrLn $ putPoint curveG
mainArgs ["ec-p"]                    = B8.putStrLn $ putHex (BigWord curveP   :: Word256)
mainArgs ["ec-n"]                    = B8.putStrLn $ putHex (BigWord curveN   :: Word256)
mainArgs ["ec-a"]                    = B8.putStrLn $ putHex (BigWord integerA :: Word256)
mainArgs ["ec-b"]                    = B8.putStrLn $ putHex (BigWord integerB :: Word256)
mainArgs ["ec-int-modp", x]          = B8.putStrLn $ putHex (BigWord (read x) :: FieldP)
mainArgs ["ec-int-modn", x]          = B8.putStrLn $ putHex (BigWord (read x) :: FieldN)
mainArgs ["ec-x", p]                 = B8.putStrLn . putHex . fromMaybe (error "invalid point") . getX $ getPoint p
mainArgs ["ec-y", p]                 = B8.putStrLn . putHex . fromMaybe (error "invalid point") . getY $ getPoint p
mainArgs ["btc", x]                  = putStrLn $ hx_btc x
mainArgs ["satoshi", x]              = putStrLn $ hx_satoshi x
mainArgs ["rfc1751-key"]             = interact hx_rfc1751_key
mainArgs ["rfc1751-mnemonic"]        = interactOneWord hx_rfc1751_mnemonic
mainArgs ("mktx":file:args)          = BS.writeFile file $ hx_mktx args
mainArgs ["sign-input",f,i,s]        = hx_sign_input f i s
mainArgs ["set-input",f,i,s]         = hx_set_input f i s
mainArgs ["validsig",f,i,s,sig]      = hx_validsig f i s sig
mainArgs _ = error $ unlines ["Unexpected arguments."
                             ,""
                             ,"Supported commands:"
                             ,"hx pubkey"
                             ,"hx addr"
                             ,"hx wif-to-secret"
                             ,"hx secret-to-wif"
                             ,"hx mktx <TXFILE> --input <TXHASH>:<INDEX> ... --output <ADDR>:<AMOUNT>"
                             ,"hx sign-input <TXFILE> <INDEX> <SCRIPT_CODE>"
                             ,"hx set-input <TXFILE> <INDEX> <SIGNATURE_AND_PUBKEY_SCRIPT>"
                             ,"hx validsig <TXFILE> <INDEX> <SCRIPT_CODE> <SIGNATURE>"
                             ,"hx hd-priv                                [0]"
                             ,"hx hd-priv <INDEX>"
                             ,"hx hd-priv --hard <INDEX>"
                             ,"hx hd-pub                                 [0]"
                             ,"hx hd-pub <INDEX>"
                             ,"hx hd-path <PATH>                         [0]"
                             ,"hx hd-to-wif"
                             ,"hx hd-to-address"
                             ,"hx hd-to-pubkey                           [0]"
                             ,"hx base58-encode"
                             ,"hx base58-decode"
                             ,"hx base58check-encode"
                             ,"hx base58check-decode"
                             ,"hx decode-addr"
                             ,"hx encode-addr"
                             ,"hx encode-addr --script                   [0]"
                             ,"hx ec-multiply  <HEX-FIELDN> <HEX-POINT>"
                             ,"hx ec-tweak-add <HEX-FIELDN> <HEX-POINT>"
                             ,"hx ec-add-modp  <HEX-FIELDP> <HEX-FIELDP>"
                             ,"hx ec-add-modn  <HEX-FIELDN> <HEX-FIELDN> [0]"
                             ,"hx ec-add       <HEX-POINT>  <HEX-POINT>  [0]"
                             ,"hx ec-double    <HEX-POINT>               [0]"
                             ,"hx ec-g                                   [0]"
                             ,"hx ec-p                                   [0]"
                             ,"hx ec-n                                   [0]"
                             ,"hx ec-a                                   [0]"
                             ,"hx ec-b                                   [0]"
                             ,"hx ec-int-p <DECIMAL-INTEGER>             [0]"
                             ,"hx ec-int-n <DECIMAL-INTEGER>             [0]"
                             ,"hx ec-x     <HEX-POINT>                   [0]"
                             ,"hx ec-x     <HEX-POINT>                   [0]"
                             ,"hx bip39-mnemonic                         [0]"
                             ,"hx bip39-hex                              [0]"
                             ,"hx bip39-seed <PASSPHRASE>                [0]"
                             ,"hx rfc1751-key                            [0]"
                             ,"hx rfc1751-mnemonic                       [0]"
                             ,"hx encode-hex                             [0]"
                             ,"hx decode-hex                             [0]"
                             ,"hx ripemd-hash"
                             ,"hx sha256"
                             ,""
                             ,"[0]: Not available in sx"
                             ,""
                             ,"PATH ::= ('M' | 'm') <PATH-CONT>"
                             ,"PATH-CONT ::= {- empty -}"
                             ,"            | '/' <INDEX> <PATH-CONT>"
                             ,"            | '/' <INDEX> '\\'' <PATH-CONT>"
                             ]

main :: IO ()
main = getArgs >>= mainArgs
