{-# LANGUAGE OverloadedStrings, TypeSynonymInstances, FlexibleInstances #-}
import Prelude hiding (interact, filter, putStr, putStrLn)
import Data.Maybe
import Data.Either (partitionEithers)
import Data.Word
import Data.Monoid
import Data.Scientific
import Data.Binary
import Data.Functor ((<$>))
import Data.Char (isDigit)
import Data.List (isPrefixOf)
import qualified Data.RFC1751 as RFC1751
import System.Environment
import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8

import Network.Haskoin.Crypto
import Network.Haskoin.Internals (FieldP, FieldN, BigWord(BigWord), Point
                                 , curveP, curveN, curveG, integerA, integerB
                                 , getX, getY, addPoint, doublePoint, mulPoint
                                 , makeInfPoint
                                 , OutPoint(OutPoint), Tx(..), Script
                                 , SigHash(SigAll), TxSignature(TxSignature)
                                 , TxIn(..)
                                 , buildAddrTx, txSigHash, encodeSig, decodeSig
                                 , getOutputAddress, decodeOutput
                                 , fromMnemonic
                                 )
import Network.Haskoin.Util
import PrettyScript
import ParseScript
import Mnemonic (hex_to_mn, mn_to_hex)
import DetailedTx (txDetailedJSON)
import Utils

readTxFile :: FilePath -> IO Tx
readTxFile file = getHex "transaction" <$> BS.readFile file

one_btc_in_satoshi :: Num a => a
one_btc_in_satoshi = 10^(8 :: Int)

class Compress a where
  compress   :: a -> a
  uncompress :: a -> a

instance Compress PrvKey where
  compress (PrvKeyU k)  = PrvKey k
  compress k@PrvKey{} = k

  uncompress (PrvKey k)  = PrvKeyU k
  uncompress k@PrvKeyU{} = k

instance Compress PubKey where
  compress (PubKeyU k)  = PubKey k
  compress k@PubKey{} = k

  uncompress (PubKey k)  = PubKeyU k
  uncompress k@PubKeyU{} = k

-- Non DER
getFieldN :: Get FieldN
getFieldN = do
  (BigWord i) <- get :: Get Word256
  unless (i < curveN) (fail $ "Get: Integer not in FieldN: " ++ show i)
  return $ fromInteger i

decodeBase58E :: BS -> BS
decodeBase58E = fromMaybe (error "invalid base58 encoding") . decodeBase58 . ignoreSpaces

xPrvImportE :: String -> XPrvKey
xPrvImportE = fromMaybe (error "invalid extended private key") . xPrvImport . ignoreSpaces

xPubImportE :: String -> XPubKey
xPubImportE = fromMaybe (error "invalid extended public key") . xPubImport . ignoreSpaces

data XKey = XPub XPubKey | XPrv XPrvKey

xKeyImport :: String -> Maybe XKey
xKeyImport s
  | "xprv" `isPrefixOf` s = XPrv <$> xPrvImport s
  | "xpub" `isPrefixOf` s = XPub <$> xPubImport s
  | otherwise             = Nothing

xKeyImportE :: String -> XKey
xKeyImportE = fromMaybe (error "invalid extended public or private key") . xKeyImport . ignoreSpaces

pubXKey :: XKey -> XPubKey
pubXKey (XPub k) = k
pubXKey (XPrv k) = deriveXPubKey k

xMasterImportE :: Hex s => s -> XPrvKey
xMasterImportE = fromMaybe (error "failed to derived private root key from seed") . makeXPrvKey
               . decodeHex "seed"

xPrvExportC :: Char -> XPrvKey -> String
xPrvExportC 'A' = addrToBase58 . xPubAddr . deriveXPubKey
xPrvExportC 'P' = putHex . xPubKey . deriveXPubKey
xPrvExportC 'p' = xPrvWIF
xPrvExportC 'U' = putHex . uncompress . xPubKey . deriveXPubKey
xPrvExportC 'u' = toWIF . uncompress . xPrvKey
xPrvExportC 'M' = xPubExport . deriveXPubKey
xPrvExportC 'm' = xPrvExport
xPrvExportC  c  = error $ "Root path expected to be m/, M/, A/, P/, p/, U/, or u/ not " ++ c : "/"

xPubExportC :: Char -> XPubKey -> String
xPubExportC 'A' = addrToBase58 . xPubAddr
xPubExportC 'P' = putHex . xPubKey
xPubExportC 'U' = putHex . uncompress . xPubKey
xPubExportC 'M' = xPubExport
xPubExportC 'u' = error "Uncompressed private keys can not be derived from extended public keys (expected P/, U/ or M/ not u/)"
xPubExportC 'p' = error "Private keys can not be derived from extended public keys (expected P/, U/ or M/ not p/)"
xPubExportC 'm' = error "Extended private keys can not be derived from extended public keys (expected M/ not m/)"
xPubExportC  c  = error $ "Root path expected to be M/, A/, or P/ not " ++ c : "/"

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
fromWIFE = fromMaybe (error "invalid WIF private key") . fromWIF . ignoreSpaces

base58ToAddrE :: String -> Address
base58ToAddrE = fromMaybe (error "invalid bitcoin address") . base58ToAddr

prvSubKeyE :: XPrvKey -> Word32 -> XPrvKey
prvSubKeyE k = fromMaybe (error "failed to derive private sub key") . prvSubKey k

primeSubKeyE :: XPrvKey -> Word32 -> XPrvKey
primeSubKeyE k = fromMaybe (error "failed to derive private prime sub key") . primeSubKey k

pubSubKeyE :: XPubKey -> Word32 -> XPubKey
pubSubKeyE k = fromMaybe (error "failed to derive public sub key") . pubSubKey k

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

getPubKey :: Hex s => s -> PubKey
getPubKey = getHex "public key"

data Key = Prv PrvKey | Pub PubKey
  deriving (Eq, Show, Read)

onKey :: (PrvKey -> a) -> (PubKey -> a) -> Key -> a
onKey onPrv _     (Prv k) = onPrv k
onKey _     onPub (Pub k) = onPub k

getKey :: String -> Key
getKey s | ('0':_) <- s = Pub $ getPubKey s
         | otherwise    = Prv $ fromWIFE  s

putKey :: Key -> String
putKey = onKey toWIF putHex

mapKey :: (PrvKey -> PrvKey) -> (PubKey -> PubKey) -> Key -> Key
mapKey onPrv onPub = onKey (Prv . onPrv) (Pub . onPub)

pubKey :: Key -> PubKey
pubKey (Prv k) = derivePubKey k
pubKey (Pub k) = k

keyAddr :: Key -> Address
keyAddr = pubKeyAddr . pubKey

keyAddrBase58 :: Key -> String
keyAddrBase58 = addrToBase58 . keyAddr

hx_compress :: String -> String
hx_compress = putKey . mapKey compress compress . getKey

hx_uncompress :: String -> String
hx_uncompress = putKey . mapKey uncompress uncompress . getKey

hx_mktx :: Hex s => [String] -> s
hx_mktx args = putHex . either error id . uncurry buildAddrTx
             . partitionEithers $ mktx_args args

hx_pubkey :: Hex s => String -> s
hx_pubkey = putHex . derivePubKey . fromWIFE

hx_addr :: String -> String
hx_addr = keyAddrBase58 . getKey

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
hx_hd_to_address = addrToBase58 . xPubAddr . pubXKey . xKeyImportE

hx_hd_to_pubkey :: Hex s => String -> s
hx_hd_to_pubkey = putHex . xPubKey . pubXKey . xKeyImportE

hx_hd_priv :: Maybe (XPrvKey -> Word32 -> XPrvKey, Word32) -> String -> String
hx_hd_priv Nothing         = xPrvExport . xMasterImportE
hx_hd_priv (Just (sub, i)) = xPrvExport . flip sub i . xPrvImportE

hx_hd_pub :: Maybe Word32 -> String -> String
hx_hd_pub Nothing  = xPubExport . deriveXPubKey     . xPrvImportE
hx_hd_pub (Just i) = xPubExport . flip pubSubKeyE i . pubXKey . xKeyImportE

hx_hd_path :: String -> String -> String
hx_hd_path []    _ = error "Empty path"
hx_hd_path (m:p) i
  | "xpub" `isPrefixOf` i = xPubExportC m . derivePubPath p $ xPubImportE    i
  | "xprv" `isPrefixOf` i = xPrvExportC m . derivePrvPath p $ xPrvImportE    i
  | otherwise             = xPrvExportC m . derivePrvPath p $ xMasterImportE i

hx_bip39_mnemonic :: Hex s => s -> String
hx_bip39_mnemonic = either error id . toMnemonic . decodeHex "seed"

hx_bip39_hex :: (Hex s, IsString s, Monoid s) => String -> s
hx_bip39_hex = putLn . encodeHex . either error id . fromMnemonic

hx_bip39_seed :: (Hex s, IsString s, Monoid s) => Passphrase -> Mnemonic -> s
hx_bip39_seed pf = putLn . encodeHex . either error id . mnemonicToSeed pf

hx_btc, hx_satoshi :: String -> String
hx_btc     = formatScientific Fixed (Just 8) . (/ one_btc_in_satoshi) . read
hx_satoshi = formatScientific Fixed (Just 0) . (* one_btc_in_satoshi) . read

hx_decode_addr :: Hex s => String -> s
hx_decode_addr = putHex . getAddrHash . base58ToAddrE

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

hx_mnemonic :: BS -> BS
hx_mnemonic s = case B8.words s of
  []  -> error "mnemonic: expects either one hexadecimal string or a list of words"
  [x] -> let (y,z) = hex_to_mn x in
         if BS.null z
           then B8.unwords y
           else error "mnemonic: invalid hex encoding"
  xs  -> mn_to_hex xs

hx_rfc1751_key :: Hex s => BS -> s
hx_rfc1751_key = encodeHex
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
     interact $ putSuccess
              . hx_validsig' tx (read i) (getHex "script" s) (getTxSig sig)
              . getPubKey
  where putSuccess :: Bool -> BS
        putSuccess True = "Status: OK\n"
        putSuccess  _   = "Status: Failed\n"

hx_sign_input :: FilePath -> String -> String -> IO ()
hx_sign_input file index script_code =
  do tx <- readTxFile file
     interactLn $ putTxSig . hx_sign_input' tx (read index) (getHex "script" script_code) . fromWIFE

-- The pure and typed counter part of hx_sign_input
hx_sign_input' :: Tx -> Int -> Script -> PrvKey -> TxSignature
hx_sign_input' tx index script_output privkey = sig where
  sh  = SigAll False
  msg = txSigHash  tx script_output index sh
  sig = TxSignature (detSignMsg msg privkey) sh

hx_rawscript :: String -> String
hx_rawscript = putHex . parseReadP parseScript

hx_showscript :: String -> String
hx_showscript = showDoc . prettyScript . getHex "script"

hx_showtx :: [String] -> IO ()
hx_showtx [file] = putStr . txDetailedJSON =<< readTxFile file
hx_showtx ("-j":xs) = hx_showtx xs
hx_showtx ("--json":xs) = hx_showtx xs
hx_showtx _ = error "Usage: hx showtx [-j|--json] <TXFILE>"

-- TODO do something better than 'read' to parse the index
parseWord32 :: String -> Word32
parseWord32 = read

getHexN :: Hex s => s -> FieldN
getHexN = runGet' getFieldN . decodeHex "field number modulo N"

getHexP :: Hex s => s -> FieldP
getHexP = getHex "field number modulo P"

-- Little endian version of getHex
getHexLE :: (Binary a, Hex s) => String -> s -> a
getHexLE msg = decode' . BS.reverse . decodeHex (msg ++ " (little endian)")

getPoint :: Hex s => s -> Point
getPoint = pubKeyPoint . getHex "curve point"

putPoint :: Hex s => Point -> s
putPoint = putHex . PubKey

mainArgs :: [String] -> IO ()
mainArgs ["pubkey"]                  = interactLn hx_pubkey
mainArgs ["addr"]                    = interactLn hx_addr
mainArgs ["wif-to-secret"]           = interactLn hx_wif_to_secret
mainArgs ["secret-to-wif"]           = interactLn hx_secret_to_wif
mainArgs ["compress"]                = interactLn hx_compress
mainArgs ["uncompress"]              = interactLn hx_uncompress
mainArgs ["hd-priv"]                 = interactLn $ hx_hd_priv   Nothing
mainArgs ["hd-priv", i]              = interactLn . hx_hd_priv $ Just (prvSubKeyE,   parseWord32 i)
mainArgs ["hd-priv", "--hard", i]    = interactLn . hx_hd_priv $ Just (primeSubKeyE, parseWord32 i)
mainArgs ["hd-pub"]                  = interactLn $ hx_hd_pub    Nothing
mainArgs ["hd-pub", i]               = interactLn . hx_hd_pub  . Just $ parseWord32 i
mainArgs ["hd-path", p]              = interactLn $ hx_hd_path p
mainArgs ["hd-to-wif"]               = interactLn hx_hd_to_wif
mainArgs ["hd-to-pubkey"]            = interactLn hx_hd_to_pubkey
mainArgs ["hd-to-address"]           = interactLn hx_hd_to_address
mainArgs ["bip39-mnemonic"]          = interactLn hx_bip39_mnemonic
mainArgs ["bip39-hex"]               = interactLn hx_bip39_hex
mainArgs ["bip39-seed", pass]        = interactLn $ hx_bip39_seed pass
mainArgs ["base58-encode"]           = interactLn hx_base58_encode
mainArgs ["base58-decode"]           = interactLn hx_base58_decode
mainArgs ["base58check-encode"]      = interactLn hx_base58check_encode
mainArgs ["base58check-decode"]      = interactLn hx_base58check_decode
mainArgs ["encode-addr", "--script"] = interactLn $ hx_encode_addr ScriptAddress
mainArgs ["encode-addr"]             = interactLn $ hx_encode_addr PubKeyAddress
mainArgs ["decode-addr"]             = interactLn hx_decode_addr
mainArgs ["validaddr",address]       = B8.putStrLn $ hx_validaddr address
mainArgs ["encode-hex"]              = interactLn encodeHex
mainArgs ["decode-hex"]              = interact $ decodeHex "input"
mainArgs ["ripemd-hash"]             = interactLn $ encodeHex . hash160BS . hash256BS
mainArgs ["ripemd160"]               = interactHex hash160BS
mainArgs ["sha256"]                  = interactHex hash256BS
mainArgs ["sha1"]                    = interactHex hashSha1BS
mainArgs ["hash256"]                 = interactHex $ hash256BS . hash256BS
mainArgs ["hash160"]                 = interactHex $ hash160BS . hash256BS
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
mainArgs ["ec-inf"]                  = B8.putStrLn $ putPoint makeInfPoint
mainArgs ["ec-int-modp", x]          = B8.putStrLn $ putHex (BigWord (read x) :: FieldP)
mainArgs ["ec-int-modn", x]          = B8.putStrLn $ putHex (BigWord (read x) :: FieldN)
mainArgs ["ec-x", p]                 = B8.putStrLn . putHex . fromMaybe (error "invalid point") . getX $ getPoint p
mainArgs ["ec-y", p]                 = B8.putStrLn . putHex . fromMaybe (error "invalid point") . getY $ getPoint p
mainArgs ["btc", x]                  = putStrLn $ hx_btc x
mainArgs ["satoshi", x]              = putStrLn $ hx_satoshi x
mainArgs ["rfc1751-key"]             = interactLn hx_rfc1751_key
mainArgs ["rfc1751-mnemonic"]        = interactLn hx_rfc1751_mnemonic
mainArgs ["mnemonic"]                = interactLn hx_mnemonic
mainArgs ("mktx":file:args)          = BS.writeFile file $ hx_mktx args
mainArgs ["sign-input",f,i,s]        = hx_sign_input f i s
mainArgs ["set-input",f,i,s]         = hx_set_input f i s
mainArgs ["validsig",f,i,s,sig]      = hx_validsig f i s sig
mainArgs ("showtx":args)             = hx_showtx args
mainArgs ["rawscript"]               = interactLn hx_rawscript
mainArgs ("rawscript":s)             = putStrLn . hx_rawscript $ unwords s
mainArgs ["showscript"]              = interactLn $ hx_showscript
mainArgs _ = error $ unlines ["Unexpected arguments."
                             ,""
                             ,"Supported commands:"
                             ,""
                             ,"hx pubkey"
                             ,"hx addr"
                             ,"hx wif-to-secret"
                             ,"hx secret-to-wif"
                             ,"hx compress                               [0]"
                             ,"hx uncompress                             [0]"
                             ,"hx mktx <TXFILE> --input <TXHASH>:<INDEX> ... --output <ADDR>:<AMOUNT>"
                             ,"hx showtx [-j|--json] <TXFILE>            [1]"
                             ,"hx sign-input <TXFILE> <INDEX> <SCRIPT_CODE>"
                             ,"hx set-input  <TXFILE> <INDEX> <SIGNATURE_AND_PUBKEY_SCRIPT>"
                             ,"hx validsig   <TXFILE> <INDEX> <SCRIPT_CODE> <SIGNATURE>"
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
                             ,"hx rawscript <SCRIPT_OP>*"
                             ,"hx showscript"
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
                             ,"hx ec-inf                                 [0]"
                             ,"hx ec-int-p <DECIMAL-INTEGER>             [0]"
                             ,"hx ec-int-n <DECIMAL-INTEGER>             [0]"
                             ,"hx ec-x     <HEX-POINT>                   [0]"
                             ,"hx ec-y     <HEX-POINT>                   [0]"
                             ,"hx mnemonic"
                             ,"hx bip39-mnemonic                         [0]"
                             ,"hx bip39-hex                              [0]"
                             ,"hx bip39-seed <PASSPHRASE>                [0]"
                             ,"hx rfc1751-key                            [0]"
                             ,"hx rfc1751-mnemonic                       [0]"
                             ,"hx encode-hex                             [0]"
                             ,"hx decode-hex                             [0]"
                             ,"hx ripemd-hash"
                             ,"hx sha256"
                             ,"hx ripemd160                              [0]"
                             ,"hx sha1                                   [0]"
                             ,"hx hash160                                [0]"
                             ,"hx hash256                                [0]"
                             ,""
                             ,"[0]: Not available in sx"
                             ,"[1]: `hx showtx` is always using JSON output,"
                             ,"     `-j` and `--json` are ignored."
                             ,""
                             ,"PATH      ::= <PATH-HEAD> <PATH-CONT>"
                             ,"PATH-HEAD ::= 'A'   [address (compressed)]"
                             ,"            | 'M'   [extended public  key]"
                             ,"            | 'm'   [extended private key]"
                             ,"            | 'P'   [public  key (compressed)]"
                             ,"            | 'p'   [private key (compressed)]"
                             ,"            | 'U'   [uncompressed public  key]"
                             ,"            | 'u'   [uncompressed private key]"
                             ,"PATH-CONT ::=                                [empty]"
                             ,"            | '/' <INDEX> <PATH-CONT>        [child key]"
                             ,"            | '/' <INDEX> '\\'' <PATH-CONT>  [hardened child key]"
                             ]

main :: IO ()
main = getArgs >>= mainArgs
