import Data.Maybe
import Data.Either (partitionEithers)
import Data.Word
import Data.Scientific
import Data.Binary
import Data.Char (isDigit)
import qualified Data.RFC1751 as RFC1751
import System.Environment
import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Builder as BSB

import Network.Haskoin.Crypto
import Network.Haskoin.Internals (FieldP, FieldN, BigWord(BigWord), Point
                                 , curveP, curveN, curveG, integerA, integerB
                                 , getX, getY, addPoint, doublePoint, mulPoint
                                 , OutPoint(OutPoint), buildAddrTx)
import Network.Haskoin.Util

interactLines :: (String -> String) -> IO ()
interactLines f = interact (unlines . map f . lines)

interactWords :: (String -> String) -> IO ()
interactWords f = interactLines (unwords . map f . words)

interactOneWord :: (String -> String) -> IO ()
interactOneWord f = interact (unlines . return . f . oneWord . map words . lines)
  where oneWord [[x]] = x
        oneWord []    = error "too few lines/words"
        oneWord [_]   = error "only one word expected on the line"
        oneWord _     = error "only one line expected"

one_btc_in_satoshi :: Num a => a
one_btc_in_satoshi = 10^(8 :: Int)

-- Non DER
getFieldN :: Get FieldN
getFieldN = do
  (BigWord i) <- get :: Get Word256
  unless (i < curveN) (fail $ "Get: Integer not in FieldN: " ++ show i)
  return $ fromInteger i

hexToBS' :: String -> BS.ByteString
hexToBS' = fromMaybe (error "invalid hex encoding") . hexToBS

decodeBase58S :: String -> BS.ByteString
decodeBase58S = fromMaybe (error "invalid base58 encoding") . decodeBase58 . B8.pack

xPrvImportE :: String -> XPrvKey
xPrvImportE = fromMaybe (error "invalid extended private key") . xPrvImport

xPubImportE :: String -> XPubKey
xPubImportE = fromMaybe (error "invalid extended public key") . xPubImport

xMasterImportE :: String -> XPrvKey
xMasterImportE = fromMaybe (error "failed to derived private root key from seed") . makeXPrvKey
               . hexToBS'

derivePath :: String -> XPrvKey -> XPrvKey
derivePath []       = id
derivePath ('/':xs) = goIndex $ span isDigit xs
  where
  goIndex ([], _)       = error "empty path segment"
  goIndex (ys, '\'':zs) = derivePath zs . flip primeSubKeyE (read ys)
  goIndex (ys, zs)      = derivePath zs . flip prvSubKeyE   (read ys)
derivePath _ = error "malformed path"

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
readOutPoint xs = OutPoint (getHexLE ys) (read zs) where (ys,zs) = splitOn ':' xs

readOutput :: String -> (String,Word64)
readOutput xs = (ys, read zs) where (ys,zs) = splitOn ':' xs

mktx_args :: [String] -> [Either OutPoint (String,Word64)]
mktx_args [] = []
mktx_args ( "--input":input :args) = Left (readOutPoint input) : mktx_args args
mktx_args (      "-i":input :args) = Left (readOutPoint input) : mktx_args args
mktx_args ("--output":output:args) = Right (readOutput output) : mktx_args args
mktx_args (      "-o":output:args) = Right (readOutput output) : mktx_args args
mktx_args _ = error "mktx_args: unexpected argument"

hx_mktx :: [String] -> String
hx_mktx args = putHex . either error id . uncurry buildAddrTx
             . partitionEithers $ mktx_args args

hx_pubkey, hx_addr, hx_wif_to_secret, hx_secret_to_wif,
  hx_hd_to_wif, hx_hd_to_address, hx_hd_to_pubkey, hx_btc, hx_satoshi,
  hx_bip39_hex, hx_bip39_mnemonic,
  hx_base58_encode, hx_base58_decode, hx_base58check_encode, hx_base58check_decode,
  hx_decode_addr, hx_rfc1751_key, hx_rfc1751_mnemonic
  :: String -> String

hx_pubkey = putHex . derivePubKey . fromWIFE

hx_addr = addrToBase58 . pubKeyAddr . decode' . hexToBS'

hx_wif_to_secret = bsToHex . runPut' . putPrvKey . fromWIFE

hx_secret_to_wif = toWIF
                 . fromMaybe (error "invalid private key") . makePrvKey
                 . bsToInteger . hexToBS'

hx_hd_to_wif = xPrvWIF . xPrvImportE

-- TODO support private keys as well
hx_hd_to_address = addrToBase58 . xPubAddr . xPubImportE

hx_hd_to_pubkey = putHex . xPubKey . xPubImportE

hx_hd_priv :: Maybe ((XPrvKey -> Word32 -> XPrvKey), Word32) -> String -> String
hx_hd_priv Nothing         = xPrvExport . xMasterImportE
hx_hd_priv (Just (sub, i)) = xPrvExport . flip sub i . xPrvImportE

hx_hd_pub :: Maybe Word32 -> String -> String
hx_hd_pub Nothing  = xPubExport . deriveXPubKey     . xPrvImportE
hx_hd_pub (Just i) = xPubExport . flip pubSubKeyE i . xPubImportE

hx_hd_path :: String -> String -> String
hx_hd_path (m:path) = f m . derivePath path . xMasterImportE
  where f 'M' = xPubExport . deriveXPubKey
        f 'm' = xPrvExport
        f  c  = error $ "Root path expected to be either 'm' or 'M' not '" ++ c : "'"
hx_hd_path path = error $ "Invalid path: " ++ show path

hx_bip39_mnemonic = either error id . toMnemonic . hexToBS'

hx_bip39_hex = (++"\n") . bsToHex . either error id . fromMnemonic

hx_bip39_seed :: Passphrase -> Mnemonic -> String
hx_bip39_seed pf = (++"\n") . bsToHex . either error id . mnemonicToSeed pf

hx_btc     = formatScientific Fixed (Just 8) . (/ one_btc_in_satoshi) . read
hx_satoshi = formatScientific Fixed (Just 0) . (* one_btc_in_satoshi) . read

hx_decode_addr = bsToHex . encode' . getAddrHash . base58ToAddrE

hx_encode_addr :: (Word160 -> Address) -> String -> String
hx_encode_addr f = addrToBase58 . f . getHex

hx_base58_encode = B8.unpack . encodeBase58 . hexToBS'

hx_base58_decode = bsToHex . decodeBase58S

hx_base58check_encode = B8.unpack . encodeBase58Check . hexToBS'

hx_base58check_decode = bsToHex
                      . fromMaybe (error "invalid base58check encoding")
                      . decodeBase58Check . B8.pack

hx_rfc1751_key      = (++"\n") . bsToHex . toStrictBS
                    . fromMaybe (error "invalid RFC1751 mnemonic") . RFC1751.mnemonicToKey

hx_rfc1751_mnemonic = fromMaybe (error "invalid RFC1751 128-key") . RFC1751.keyToMnemonic . toLazyBS . hexToBS'

-- TODO do something better than 'read' to parse the index
parseWord32 :: String -> Word32
parseWord32 = read

-- | Encode a bytestring to a base16 (HEX) representation
bsToHex' :: BS.ByteString -> BS.ByteString
bsToHex' = toStrictBS . BSB.toLazyByteString . BSB.byteStringHex

putHex :: Binary a => a -> String
putHex = bsToHex . encode'

getHexN :: String -> FieldN
getHexN = runGet' getFieldN . hexToBS'

getHex :: Binary a => String -> a
getHex = runGet' get . hexToBS'

-- Little endian version of getHex
getHexLE :: Binary a => String -> a
getHexLE = runGet' get . BS.reverse . hexToBS'

getPoint :: String -> Point
getPoint = pubKeyPoint . getHex

putPoint :: Point -> String
putPoint = putHex . PubKey

mainArgs :: [String] -> IO ()
mainArgs ["pubkey"]                  = interactWords hx_pubkey
mainArgs ["addr"]                    = interactWords hx_addr
mainArgs ["wif-to-secret"]           = interactWords hx_wif_to_secret
mainArgs ["secret-to-wif"]           = interactWords hx_secret_to_wif
mainArgs ["hd-priv"]                 = interactWords $ hx_hd_priv   Nothing
mainArgs ["hd-priv", i]              = interactWords . hx_hd_priv $ Just (prvSubKeyE,   parseWord32 i)
mainArgs ["hd-priv", "--hard", i]    = interactWords . hx_hd_priv $ Just (primeSubKeyE, parseWord32 i)
mainArgs ["hd-pub"]                  = interactWords $ hx_hd_pub    Nothing
mainArgs ["hd-pub", i]               = interactWords . hx_hd_pub  . Just $ parseWord32 i
mainArgs ["hd-path", p]              = interactWords $ hx_hd_path p
mainArgs ["hd-to-wif"]               = interactWords hx_hd_to_wif
mainArgs ["hd-to-pubkey"]            = interactWords hx_hd_to_pubkey
mainArgs ["hd-to-address"]           = interactWords hx_hd_to_address
mainArgs ["bip39-mnemonic"]          = interactWords hx_bip39_mnemonic
mainArgs ["bip39-hex"]               = interact hx_bip39_hex
mainArgs ["bip39-seed", pass]        = interact $ hx_bip39_seed pass
mainArgs ["base58-encode"]           = interactWords hx_base58_encode
mainArgs ["base58-decode"]           = interactWords hx_base58_decode
mainArgs ["base58check-encode"]      = interactWords hx_base58check_encode
mainArgs ["base58check-decode"]      = interactWords hx_base58check_decode
mainArgs ["encode-addr", "--script"] = interactWords $ hx_encode_addr ScriptAddress
mainArgs ["encode-addr"]             = interactWords $ hx_encode_addr PubKeyAddress
mainArgs ["decode-addr"]             = interactWords hx_decode_addr
mainArgs ["ripemd-hash"]             = BS.interact $ bsToHex' . hash160BS
mainArgs ["sha256"]                  = BS.interact $ bsToHex' . hash256BS
mainArgs ["ec-double", p]            = putStrLn . putPoint . doublePoint $ getPoint p
mainArgs ["ec-add", p, q]            = putStrLn . putPoint $ addPoint (getPoint p) (getPoint q)
mainArgs ["ec-multiply", x, p]       = putStrLn . putPoint $ mulPoint (getHexN x) (getPoint p)
mainArgs ["ec-tweak-add", x, p]      = putStrLn . putPoint $ addPoint (mulPoint (getHexN x) curveG) (getPoint p)
mainArgs ["ec-add-modp", x, y]       = putStrLn $ putHex (getHex x + getHex y :: FieldP)
mainArgs ["ec-add-modn", x, y]       = putStrLn $ putHex (getHexN x + getHexN y :: FieldN)
mainArgs ["ec-g"]                    = putStrLn $ putPoint curveG
mainArgs ["ec-p"]                    = putStrLn $ putHex (BigWord curveP   :: Word256)
mainArgs ["ec-n"]                    = putStrLn $ putHex (BigWord curveN   :: Word256)
mainArgs ["ec-a"]                    = putStrLn $ putHex (BigWord integerA :: Word256)
mainArgs ["ec-b"]                    = putStrLn $ putHex (BigWord integerB :: Word256)
mainArgs ["ec-int-modp", x]          = putStrLn $ putHex (BigWord (read x) :: FieldP)
mainArgs ["ec-int-modn", x]          = putStrLn $ putHex (BigWord (read x) :: FieldN)
mainArgs ["ec-x", p]                 = putStrLn . putHex . fromMaybe (error "invalid point") . getX $ getPoint p
mainArgs ["ec-y", p]                 = putStrLn . putHex . fromMaybe (error "invalid point") . getY $ getPoint p
mainArgs ["btc", x]                  = putStrLn $ hx_btc x
mainArgs ["satoshi", x]              = putStrLn $ hx_satoshi x
mainArgs ["rfc1751-key"]             = interact hx_rfc1751_key
mainArgs ["rfc1751-mnemonic"]        = interactOneWord hx_rfc1751_mnemonic
mainArgs ("mktx":file:args)          = writeFile file $ hx_mktx args
mainArgs _ = error $ unlines ["Unexpected arguments."
                             ,""
                             ,"Supported commands:"
                             ,"hx pubkey"
                             ,"hx addr"
                             ,"hx wif-to-secret"
                             ,"hx secret-to-wif"
                             ,"hx mktx <TXFILE> --input <TXHASH>:<INDEX> ... --output <ADDR>:<AMOUNT>"
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
                             ,"hx ripemd-hash                            [1]"
                             ,"hx sha256                                 [1]"
                             ,""
                             ,"[0]: Not available in sx"
                             ,"[1]: The output is consistent with openssl but NOT with sx"
                             ,"PATH ::= ('M' | 'm') <PATH-CONT>"
                             ,"PATH-CONT ::= {- empty -}"
                             ,"            | '/' <INDEX> <PATH-CONT>"
                             ,"            | '/' <INDEX> '\\'' <PATH-CONT>"
                             ]

main :: IO ()
main = getArgs >>= mainArgs
