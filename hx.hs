{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Context (ctx)
import Control.Applicative ((<|>))
import Control.Exception
import Control.Monad (unless, when)
import Crypto.Hash (HashAlgorithm)
import Crypto.Hash.Algorithms (SHA1 (..), SHA224 (..), SHA256 (..), SHA384 (..), SHA512 (..))
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Crypto.MAC.HMAC (HMAC, hmac)
import qualified Crypto.RFC1751 as RFC1751
import qualified Crypto.Secp256k1 as Secp
import qualified Data.Aeson as A
import qualified Data.ByteArray as BA
import Data.Bytes.Get (runGetS)
import Data.Bytes.Serial (deserialize)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Data.Char (isDigit, toLower)
import Data.Foldable (foldlM)
import Data.List (stripPrefix)
import Data.Maybe (fromMaybe, isJust, isNothing)
import Data.Scientific (FPFormat (Fixed), formatScientific)
import qualified Data.Text as T
import Data.Word (Word32, Word64)
import DetailedTx (outputType, scriptDetails, txDetails, xPrvDetails, xPubDetails)
import Output
import EC
import Electrum
import Haskoin hiding (decodeHex, encodeHex)
import Haskoin.Crypto.Keys.Slip39 (Scheme (..), combineMnemonics, generateMnemonics)
import Keys
import Message
import Mnemonic (bytes_to_mn, mn_to_bytes)
import ParseScript
import PrettyScript
import System.Directory (doesFileExist)
import System.Entropy (getEntropy)
import System.Environment (getArgs, lookupEnv)
import System.Exit
import System.IO (IOMode (ReadMode), hPutStrLn, openBinaryFile, stderr)
import Utils

------------------------------------------------------------------------------
-- Transactions files

type TxFile = BS

readTx :: BS -> Tx
readTx = decodeS "transaction" . decodeHex "transaction"

readTxFile :: TxFile -> IO Tx
readTxFile "-" = readTx <$> BS.getContents
readTxFile file = readTx <$> readFileBS file

readFileBS :: BS -> IO BS
readFileBS f = do
  h <- openBinaryFile (B8.unpack f) ReadMode
  BS.hGetContents h

putTx :: Tx -> BS
putTx = putHex

one_btc_in_satoshi :: (Num a) => a
one_btc_in_satoshi = 10 ^ (8 :: Int)

------------------------------------------------------------------------------
-- Keys

decodeBase58E :: BS -> BS
decodeBase58E = fromMaybe (error "invalid base58 encoding") . decodeBase58 . toText . ignoreSpaces

hx_compress :: Network -> BS -> BS
hx_compress net = putKey net . compressKey . getKey net

hx_uncompress :: Network -> BS -> BS
hx_uncompress net = putKey net . uncompressKey . getKey net

hx_pubkey :: Network -> [BS] -> BS -> BS
hx_pubkey net args = putPubKey . compressIf . pubKeyOf . compat . getKey net
  where
    compressIf :: PublicKey -> PublicKey
    compressIf = case args of
      [] -> id
      [o]
        | B8.map toLower o `elem` ["1", "true", "yes", "--compressed", "-c"] -> \k -> PublicKey k.point True
        | B8.map toLower o `elem` ["0", "false", "no", "--uncompressed", "-u"] -> \k -> PublicKey k.point False
      _ -> error "Usage: hx pubkey [--uncompressed|--compressed]"

    -- This is for compatibility with `sx', namely if one gives a
    -- compressed public key with no compression argument the key
    -- is uncompressed.
    compat (Pub k) = Pub (PublicKey k.point False)
    compat k = k

addrTypeOpt :: [BS] -> (AddrType, [BS])
addrTypeOpt args = (maybe AddrP2PKH parseAddrType t, rest)
  where
    (t, rest) = takeOpt1 ["--type", "-t"] args

hx_addr :: Network -> [BS] -> BS -> BS
hx_addr net args =
  no_args "hx addr [--type p2pkh|p2wpkh|p2sh-p2wpkh|p2tr]" rest $
    addrText net . addrOfPub ty . pubKeyOf . getKey net
  where
    (ty, rest) = addrTypeOpt args

hx_xonly_pubkey :: Network -> BS -> BS
hx_xonly_pubkey net = encodeHex . xOnlyBytes . pubKeyOf . getKey net

hx_wif_to_secret :: Network -> BS -> BS
hx_wif_to_secret net = encodeHex . (.key.get) . fromWifE net

hx_secret_to_wif :: Network -> [BS] -> BS -> BS
hx_secret_to_wif net args =
  toWifBS net . wrapSecKey compressed . secKeyE . decodeHex "private key"
  where
    (unc, rest) = takeFlag ["--uncompressed", "-u"] args
    compressed = no_args "hx secret-to-wif [--uncompressed]" rest (not unc)

newSecKey :: IO SecKey
newSecKey = do
  bytes <- getEntropy 32
  maybe newSecKey return (Secp.secKey bytes)

hx_newkey :: Network -> [BS] -> IO ()
hx_newkey net args = do
  let (unc, rest) = takeFlag ["--uncompressed", "-u"] args
  no_args "hx newkey [--uncompressed]" rest (return ())
  k <- newSecKey
  emit . toWifBS net $ wrapSecKey (not unc) k

brainwallet :: Network -> BS -> BS
brainwallet net = toWifBS net . wrapSecKey False . secKeyE . sha256BS

hx_brainwallet :: Network -> [BS] -> BS
hx_brainwallet net [x] = brainwallet net x
hx_brainwallet _ [] = error . brainwallet_usage $ "too few arguments"
hx_brainwallet _ (x : _)
  | "-" `BS.isPrefixOf` x = error . brainwallet_usage $ "unexpected argument, " ++ show x
  | otherwise = error . brainwallet_usage $ "too many arguments"

brainwallet_usage :: String -> String
brainwallet_usage m = unlines [m, "Usage: hx brainwallet <PASSPHRASE>"]

hx_mini_to_wif :: Network -> BS -> BS
hx_mini_to_wif net =
  toWifBS net . fromMaybe (error "invalid mini private key") . fromMiniKey . trim

------------------------------------------------------------------------------
-- Extended keys (BIP32)

xPrvImportE :: Network -> BS -> XPrvKey
xPrvImportE net s0 =
  case xPrvImport net (toText s) of
    Just k -> k
    Nothing
      | isHex (B8.unpack s) -> makeXPrvKey (decodeHex "seed" s)
      | otherwise -> error "invalid extended private key"
  where
    s = ignoreSpaces s0

data XK = XKPub XPubKey | XKPrv XPrvKey

xKeyImportE :: Network -> BS -> XK
xKeyImportE net s0 =
  case xPubImport net ctx (toText s) of
    Just k -> XKPub k
    Nothing -> XKPrv (xPrvImportE net s)
  where
    s = ignoreSpaces s0

pubXK :: XK -> XPubKey
pubXK (XKPub k) = k
pubXK (XKPrv k) = deriveXPubKey ctx k

xPubPublicKey :: XPubKey -> PublicKey
xPubPublicKey k = wrapPubKey True k.key

xKeyExportC :: Network -> Char -> XK -> BS
xKeyExportC net c k = case c of
  'A' -> addr AddrP2PKH
  'W' -> addr AddrP2WPKH
  'S' -> addr AddrP2SH_P2WPKH
  'T' -> addr AddrP2TR
  'P' -> putPubKey pub
  'U' -> putPubKey (PublicKey pub.point False)
  'X' -> encodeHex (xOnlyBytes pub)
  'M' -> fromText (xPubExport net ctx (pubXK k))
  'p' -> prv "p/" (fromText . xPrvWif net)
  'u' -> prv "u/" (\x -> toWifBS net (PrivateKey x.key False))
  'm' -> prv "m/" (fromText . xPrvExport net)
  _ ->
    error $
      "Root path expected to be one of m/, M/, A/, W/, S/, T/, P/, U/, X/, p/ or u/, not "
        ++ c
        : "/"
  where
    pub = xPubPublicKey (pubXK k)
    addr ty = addrText net (addrOfPub ty pub)
    prv what f = case k of
      XKPrv x -> f x
      XKPub _ -> error $ "Private keys can not be derived from extended public keys (" ++ what ++ " is not allowed here)"

-- | Parse a path like @/44'/0'/0'/0/1@ (hardened with ', h or H). The first
-- argument prefixes error messages.
parsePathSteps :: String -> String -> [(Bool, Word32)]
parsePathSteps _ [] = []
parsePathSteps who ('/' : xs) = case span isDigit xs of
  ([], _) -> error $ who ++ ": empty path segment"
  (ys, z : zs) | z `elem` ("'hH" :: String) -> (True, index ys) : parsePathSteps who zs
  (ys, zs) -> (False, index ys) : parsePathSteps who zs
  where
    index ys =
      let i = read ys :: Integer
       in if i < 0x80000000 then fromInteger i else error $ who ++ ": path index too large (must be below 2^31)"
parsePathSteps _ _ = error "malformed path"

derivePathXK :: [(Bool, Word32)] -> XK -> XK
derivePathXK steps k0 = foldl step k0 steps
  where
    step (XKPrv k) (True, i) = XKPrv (hardSubKey ctx k i)
    step (XKPrv k) (False, i) = XKPrv (prvSubKey ctx k i)
    step (XKPub _) (True, _) = error "derivePubPath: hardened subkeys are inaccessible from extended public keys"
    step (XKPub k) (False, i) = XKPub (pubSubKey ctx k i)

hx_hd_path :: Network -> BS -> BS -> BS
hx_hd_path net mp s =
  case B8.unpack mp of
    [] -> error "Empty path"
    (m : p) -> xKeyExportC net m (derivePathXK (parsePathSteps who p) k)
  where
    k = xKeyImportE net s
    who = case k of
      XKPrv _ -> "derivePrvPath"
      XKPub _ -> "derivePubPath"

hx_hd_priv :: Network -> Maybe (Bool, Word32) -> BS -> BS
hx_hd_priv net Nothing = fromText . xPrvExport net . makeXPrvKey . decodeHex "seed"
hx_hd_priv net (Just (hard, i)) =
  fromText . xPrvExport net . (\k -> (if hard then hardSubKey else prvSubKey) ctx k i) . xPrvImportE net

hx_hd_pub :: Network -> Maybe Word32 -> BS -> BS
hx_hd_pub net mi = fromText . xPubExport net ctx . f . pubXK . xKeyImportE net
  where
    f = maybe id (flip (pubSubKey ctx)) mi

hx_hd_decode :: Network -> BS -> Val
hx_hd_decode net s = case xKeyImportE net s of
  XKPrv k -> xPrvDetails net k
  XKPub k -> xPubDetails net k

hx_hd_to_wif :: Network -> BS -> BS
hx_hd_to_wif net = fromText . xPrvWif net . xPrvImportE net

hx_hd_to_address :: Network -> [BS] -> BS -> BS
hx_hd_to_address net args =
  no_args "hx hd-to-address [--type p2pkh|p2wpkh|p2sh-p2wpkh|p2tr]" rest $
    addrText net . addrOfPub ty . xPubPublicKey . pubXK . xKeyImportE net
  where
    (ty, rest) = addrTypeOpt args

hx_hd_to_pubkey :: Network -> BS -> BS
hx_hd_to_pubkey net = putPubKey . xPubPublicKey . pubXK . xKeyImportE net

------------------------------------------------------------------------------
-- Mnemonics

hx_bip39_mnemonic :: BS -> BS
hx_bip39_mnemonic = either error fromText . toMnemonic . decodeHex "mnemonic-as-hex"

hx_bip39_hex :: BS -> BS
hx_bip39_hex = encodeHex . either error id . fromMnemonic . toText . trim

hx_bip39_seed :: BS -> BS -> BS
hx_bip39_seed pf = encodeHex . either error id . mnemonicToSeed (toText pf) . f . trim
  where
    f s
      | isHex (B8.unpack s) = either (const (toText s)) id (toMnemonic (decodeHex "seed" s))
      | otherwise = toText s

hx_bip39_new :: [BS] -> IO ()
hx_bip39_new args = do
  let n = case args of
        [] -> 24
        [w] -> parseInt "number of words" w
        _ -> error "Usage: hx bip39-new [<12|15|18|21|24>]"
  unless (n `elem` [12, 15, 18, 21, 24]) $
    error "The number of words must be 12, 15, 18, 21 or 24"
  ent <- getEntropy (n * 4 `div` 3)
  emit . either error fromText $ toMnemonic ent

hx_slip39_split :: [BS] -> IO ()
hx_slip39_split args = case args of
  (t : n : rest) -> do
    let pass = case rest of
          [] -> ""
          [p] -> toText p
          _ -> usageErr
        threshold = parseInt "threshold" t
        count = parseInt "share count" n
    secret <- decodeHex "master secret" <$> BS.getContents
    r <- generateMnemonics (Scheme 1 [(threshold, count)]) True 1 pass secret
    case r of
      Left e -> error e
      Right groups -> emit (toVal (concat groups))
  _ -> usageErr
  where
    usageErr = error "Usage: hx slip39-split <THRESHOLD> <SHARES> [<PASSPHRASE>]"

hx_slip39_combine :: [BS] -> IO ()
hx_slip39_combine args = do
  let pass = case args of
        [] -> ""
        [p] -> toText p
        _ -> error "Usage: hx slip39-combine [<PASSPHRASE>]"
  shares <- readList' <$> BS.getContents
  emit . encodeHex . either error id $ combineMnemonics pass shares

-- | Read a list of strings: a JSON array, a YAML list ("- " items) or one
-- item per line.
readList' :: BS -> [T.Text]
readList' input
  | Just items <- A.decodeStrict (trim input) = items
  | otherwise = filter (not . T.null) . map (unquote . dropDash . T.strip) . T.lines $ toText input
  where
    dropDash l = maybe l T.strip (T.stripPrefix "- " l)
    unquote l = fromMaybe l (A.decodeStrict (fromText l))

hx_mnemonic :: BS -> BS
hx_mnemonic s = case B8.words s of
  [] -> error "mnemonic: expects either one hexadecimal string or a list of words"
  [x] -> B8.unwords (bytes_to_mn (decodeHex "mnemonic: hex input" x))
  xs -> encodeHex (mn_to_bytes xs)

hx_rfc1751_key :: BS -> BS
hx_rfc1751_key =
  encodeHex
    . fromMaybe (error "invalid RFC1751 mnemonic")
    . RFC1751.mnemonicToKey
    . B8.unpack
    . trim

hx_rfc1751_mnemonic :: BS -> BS
hx_rfc1751_mnemonic =
  B8.pack
    . fromMaybe (error "invalid RFC1751 128 bits key")
    . RFC1751.keyToMnemonic
    . decodeHex "128 bits key"

------------------------------------------------------------------------------
-- Amounts

hx_btc, hx_satoshi :: BS -> BS
hx_btc = B8.pack . formatScientific Fixed (Just 8) . (/ one_btc_in_satoshi) . readBS
hx_satoshi = B8.pack . formatScientific Fixed (Just 0) . (* one_btc_in_satoshi) . readBS

------------------------------------------------------------------------------
-- Addresses


hx_validaddr :: Network -> BS -> Verdict
hx_validaddr net = Verdict . isJust . textToAddr net . T.strip . toText

hx_decode_addr :: Network -> BS -> BS
hx_decode_addr net = encodeHex . addressBytes . parseAddr net

data EncodeAs = EncodeAs [BS] (BS -> Maybe Address)

encodeAsOptions :: [EncodeAs]
encodeAsOptions =
  [ EncodeAs ["--p2pkh"] (fmap p2pkhAddr . h160),
    EncodeAs ["--script", "--p2sh"] (fmap p2shAddr . h160),
    EncodeAs ["--p2wpkh"] (fmap p2wpkhAddr . h160),
    EncodeAs ["--p2wsh"] (fmap p2wshAddr . h256),
    EncodeAs ["--p2tr"] (witnessAddress 1 . len 32),
    EncodeAs ["--p2sh32"] (fmap script32Address . h256),
    EncodeAs ["--token-p2pkh"] (cashAddress 2 . len 20),
    EncodeAs ["--token-p2sh"] (\b -> cashAddress 3 b)
  ]
  where
    len n b = if BS.length b == n then b else error ("expected " ++ show n ++ " bytes")
    h160 = eitherToMaybe . runGetS deserialize . len 20
    h256 = eitherToMaybe . runGetS deserialize . len 32

hx_encode_addr :: Network -> [BS] -> BS -> BS
hx_encode_addr net args =
  addrText net . fromMaybe (error "cannot encode this address") . f . decodeHex "address"
  where
    f = case args of
      [] -> fmap p2pkhAddr . eitherToMaybe . runGetS deserialize
      [o] | EncodeAs _ g : _ <- [e | e@(EncodeAs ns _) <- encodeAsOptions, o `elem` ns] -> g
      _ -> error "Usage: hx encode-addr [--p2pkh|--p2sh|--p2wpkh|--p2wsh|--p2tr|--p2sh32|--token-p2pkh|--token-p2sh]"

addrTypeName :: Address -> T.Text
addrTypeName a = case a of
  PubKeyAddress {} -> "p2pkh"
  ScriptAddress {} -> "p2sh"
  WitnessPubKeyAddress {} -> "p2wpkh"
  WitnessScriptAddress {} -> "p2wsh"
  WitnessAddress 1 b | BS.length b == 32 -> "p2tr"
  WitnessAddress {} -> "witness_unknown"
  Script32Address {} -> "p2sh32"
  CashAddress 2 _ -> "token-p2pkh"
  CashAddress 3 _ -> "token-p2sh"
  CashAddress {} -> "cash_unknown"

-- | Bitcoin Cash forms of an address: legacy, CashAddr and token-aware.
cashForms :: Network -> Address -> [(T.Text, Val)]
cashForms net a
  | not (isCashNet net) = []
  | otherwise =
      [ "legacy" .: addrToBase58 net (plain a),
        "cashaddr" .: addrToCash net (plain a),
        "token" .: (tokenAware a >>= addrToCash net)
      ]

plain :: Address -> Address
plain (CashAddress 2 b) = fromMaybe (error "invalid address") (cashAddress 0 b)
plain (CashAddress 3 b) = fromMaybe (error "invalid address") (cashAddress 1 b)
plain a = a

tokenAware :: Address -> Maybe Address
tokenAware a = case a of
  PubKeyAddress h -> cashAddress 2 (encodeS h)
  ScriptAddress h -> cashAddress 3 (encodeS h)
  Script32Address h -> cashAddress 3 (encodeS h)
  CashAddress 2 _ -> Just a
  CashAddress 3 _ -> Just a
  _ -> Nothing

hx_addr_info :: Network -> BS -> Val
hx_addr_info net s =
  obj $
    [ "address" .: addrText net a,
      "network" .: T.pack net.name,
      "type" .: addrTypeName a,
      "version" .: addressVersion a,
      "hash" .: encodeHex (addressBytes a),
      "script" .: (scriptDetails net <$> addressToScriptBS ctx (plain a))
    ]
      ++ cashForms net a
  where
    a = parseAddr net s

hx_addr_convert :: Network -> [BS] -> BS -> BS
hx_addr_convert net args s =
  case args of
    ["--to", fmt] -> conv (B8.map toLower fmt)
    _ -> usageErr
  where
    usageErr = error "Usage: hx addr-convert --to legacy|cashaddr|token [<ADDRESS>]"
    a = parseAddr net s
    conv "legacy" = fromText . fromMaybe (error "this address has no legacy form") $ addrToBase58 net (plain a)
    conv "cashaddr" = fromText . fromMaybe (error "CashAddr requires a Bitcoin Cash network (use -n bch)") $ addrToCash net (plain a)
    conv "token" = fromText . fromMaybe (error "this address has no token-aware CashAddr form") $ tokenAware a >>= addrToCash net
    conv _ = usageErr

hx_addr_to_script :: Network -> BS -> BS
hx_addr_to_script net =
  encodeHex . fromMaybe (error "this address has no output script") . addressToScriptBS ctx . plain . parseAddr net

hx_script_to_addr :: Network -> BS -> BS
hx_script_to_addr net =
  addrText net . either error id . scriptToAddressBS net ctx . decodeHex "script"

hx_script_addr :: Network -> [BS] -> BS -> BS
hx_script_addr net args s =
  addrText net $ case args of
    [] -> p2sh
    ["--p2sh"] -> p2sh
    ["--p2wsh"] -> p2wsh
    ["--p2sh-p2wsh"] -> p2shAddr . addressHash $ witnessProgram
    ["--p2sh32"] -> script32Address (doubleSHA256 script)
    _ -> error "Usage: hx script-addr [--p2sh|--p2wsh|--p2sh-p2wsh|--p2sh32] [<REDEEM-SCRIPT>]"
  where
    script = decodeHex "redeem script" s
    p2sh = p2shAddr (addressHash script)
    p2wsh = p2wshAddr (sha256 script)
    witnessProgram = BS.pack [0x00, 0x20] <> encodeS (sha256 script)

hx_multisig :: [BS] -> BS
hx_multisig args0 =
  case rest of
    (m : keys@(_ : _)) ->
      let ks = map getPubKey keys
          so = PayMulSig ks (parseInt "number of required signatures" m)
          so' = if sorted then sortMulSig ctx so else so
       in encodeHex . encodeS . either error id $ encodeOutput ctx so'
    _ -> error "Usage: hx multisig [--sort] <M> <PUBKEY>..."
  where
    (sorted, rest) = takeFlag ["--sort", "-s"] args0

------------------------------------------------------------------------------
-- Base58, checksums, encodings

hx_base58_encode :: BS -> BS
hx_base58_encode = fromText . encodeBase58 . decodeHex "input"

hx_base58_decode :: BS -> BS
hx_base58_decode = encodeHex . decodeBase58E

hx_base58check_encode :: [BS] -> BS -> BS
hx_base58check_encode args = fromText . encodeBase58Check . BS.cons ver . decodeHex "input"
  where
    ver = case args of
      [] -> 1
      [x] -> parseWord8 "version byte" x
      _ -> error "Usage: hx base58check-encode [<VERSION-BYTE>]"

hx_base58check_decode :: [BS] -> BS -> Val
hx_base58check_decode args
  | null args = wrap . BS.uncons . chksum32_decode . decodeBase58E
  | otherwise = error "Usage: hx base58check-decode"
  where
    wrap (Just (x, xs)) = obj ["version" .: x, "payload" .: encodeHex xs]
    wrap Nothing = error "empty base58check payload"

chksum32_encode :: BS -> BS
chksum32_encode d = d <> chksum32BS d

chksum32_decode :: BS -> BS
chksum32_decode d
  | BS.length d >= 4 && chksum32BS pre == post = pre
  | otherwise = error "checksum does not match"
  where
    (pre, post) = BS.splitAt (BS.length d - 4) d

hx_chksum32 :: [BS] -> BS
hx_chksum32 = withHex chksum32BS . BS.concat

hx_chksum32_encode :: [BS] -> BS
hx_chksum32_encode = withHex chksum32_encode . BS.concat

hx_chksum32_decode :: [BS] -> BS
hx_chksum32_decode = withHex chksum32_decode . BS.concat

hx_bech32_encode :: [BS] -> BS -> BS
hx_bech32_encode args input = case args' of
  [hrp] ->
    fromText . fromMaybe (error "cannot encode as bech32") $
      bech32Encode enc (toText hrp) (toBase32 (BS.unpack (decodeHex "data" input)))
  _ -> error "Usage: hx bech32-encode [--m] <HRP> [<HEX-DATA>]"
  where
    (m, args') = takeFlag ["--m", "--bech32m"] args
    enc = if m then Bech32m else Bech32

hx_bech32_decode :: BS -> Val
hx_bech32_decode s =
  case bech32Decode (T.toLower (T.strip (toText s))) of
    Nothing -> error "invalid bech32 string"
    Just (enc, hrp, dat) ->
      obj
        [ "hrp" .: hrp,
          "encoding" .: (if enc == Bech32m then "bech32m" else "bech32" :: T.Text),
          "data" .: (encodeHex . BS.pack . fromMaybe (error "invalid bech32 data padding") $ toBase256 dat)
        ]

------------------------------------------------------------------------------
-- Signatures

hx_verifysig_modn :: [BS] -> Verdict
hx_verifysig_modn [m, pub, sigHex] =
  Verdict $ case Secp.importSig ctx (decodeHex "signature" sigHex) of
    Nothing -> False
    Just s -> verifyHashSig ctx (hashOfModN m) s (getPubKey pub).point
hx_verifysig_modn _ = error "Usage: hx verifysig-modn <MESSAGE-DECIMAL-INTEGER> <PUBKEY> <SIGNATURE>"

hashOfModN :: BS -> Hash256
hashOfModN m = decodeS "message" (integerToBytes32 i)
  where
    i0 = readDigits "integer modulo n in decimal" m :: Integer
    i = if i0 < curveN then i0 else error $ "Integer not in FieldN: " ++ show i0

hx_signmsg_modn :: Network -> [BS] -> BS
hx_signmsg_modn net [m, prv] =
  encodeHex . Secp.exportSig ctx $ signHash ctx (fromWifE net prv).key (hashOfModN m)
hx_signmsg_modn _ _ = error "Usage: hx signmsg-modn <MESSAGE-DECIMAL-INTEGER> <PRIVKEY>"

hx_sign_hash :: Network -> [BS] -> BS
hx_sign_hash net [prv, h] =
  encodeHex . Secp.exportSig ctx $ signHash ctx (fromWifE net prv).key (hash256E h)
hx_sign_hash _ _ = error "Usage: hx sign-hash <PRIVKEY> <HEX-HASH32>"

hx_verify_hash :: [BS] -> Verdict
hx_verify_hash [pub, sigHex, h] =
  Verdict $ case Secp.importSig ctx (decodeHex "signature" sigHex) of
    Nothing -> False
    Just s -> verifyHashSig ctx (hash256E h) s (getPubKey pub).point
hx_verify_hash _ = error "Usage: hx verify-hash <PUBKEY> <DER-SIGNATURE> <HEX-HASH32>"

schnorrMsg :: BS -> Secp.Msg
schnorrMsg = fromMaybe (error "invalid message") . Secp.msg . decodeHexBytes "message" 32

hx_schnorr_sign :: Network -> [BS] -> BS
hx_schnorr_sign net [prv, m] =
  encodeHex . (.get) $ Secp.signSchnorr ctx (fromWifE net prv).key (schnorrMsg m)
hx_schnorr_sign _ _ = error "Usage: hx schnorr-sign <PRIVKEY> <HEX-MESSAGE32>"

hx_schnorr_verify :: [BS] -> Verdict
hx_schnorr_verify [pub, sigHex, m] =
  Verdict . fromMaybe False $ do
    p <- Secp.importXOnlyPubKey ctx (decodeHexBytes "x-only public key" 32 pub)
    s <- Secp.schnorrSig (decodeHexBytes "Schnorr signature" 64 sigHex)
    return $ Secp.verifySchnorr ctx p s (schnorrMsg m)
hx_schnorr_verify _ = error "Usage: hx schnorr-verify <XONLY-PUBKEY> <SIGNATURE> <HEX-MESSAGE32>"

hx_message_sign :: Network -> [BS] -> BS
hx_message_sign net args0 = case args of
  [prv, m] -> signMessage ty (fromWifE net prv) m
  _ -> error "Usage: hx message-sign [--type p2pkh|p2wpkh|p2sh-p2wpkh] <PRIVKEY> <MESSAGE>"
  where
    (ty, args) = addrTypeOpt args0

hx_message_verify :: Network -> [BS] -> Verdict
hx_message_verify net [a, sigB64, m] =
  Verdict . either (const False) id $ verifyMessage (parseAddr net a) sigB64 m
hx_message_verify _ _ = error "Usage: hx message-verify <ADDRESS> <SIGNATURE> <MESSAGE>"

------------------------------------------------------------------------------
-- Transactions

readOutPoint :: BS -> OutPoint
readOutPoint xs =
  OutPoint
    (getHexLE "transaction hash" ys)
    (parseWord32 "output point index" zs)
  where
    (ys, zs) = splitOnBS ':' (trim xs)

-- | ADDRESS:AMOUNT, splitting on the last colon as CashAddr addresses may
-- carry a "bitcoincash:" prefix.
readOutput :: Network -> BS -> TxOut
readOutput net xs = TxOut amount script
  where
    s = trim xs
    (ys, zs) = B8.spanEnd (/= ':') s
    a = BS.take (BS.length ys - 1) ys
    amount = parseWord64 "output amount" zs
    script =
      fromMaybe (error "this address has no output script")
        . addressToScriptBS ctx
        . plain
        $ parseAddr net a

dataOutput :: BS -> TxOut
dataOutput h = TxOut 0 (encodeS . either error id $ encodeOutput ctx (DataCarrier [decodeHex "data" h]))

data MkTx = MkTx {ins :: [OutPoint], outs :: [TxOut], ver :: Word32, lock :: Word32, sq :: Word32}

hx_mktx :: Network -> [BS] -> BS
hx_mktx net args0 = putTx (Tx o.ver [TxIn op "" o.sq | op <- o.ins] o.outs [] o.lock)
  where
    o = go args0 (MkTx [] [] 1 0 0xffffffff)
    go [] m = m {ins = reverse m.ins, outs = reverse m.outs}
    go (f : v : args) m
      | f `elem` ["--input", "-i"] = go args m {ins = readOutPoint v : m.ins}
      | f `elem` ["--output", "-o"] = go args m {outs = readOutput net v : m.outs}
      | f `elem` ["--data", "-d"] = go args m {outs = dataOutput v : m.outs}
      | f == "--version" = go args m {ver = parseWord32 "version" v}
      | f == "--locktime" = go args m {lock = parseWord32 "locktime" v}
      | f == "--sequence" = go args m {sq = parseWord32 "sequence" v}
    go ("--rbf" : args) m = go args m {sq = 0xfffffffd}
    go (arg : _) _ = error $ "mktx: unexpected argument " ++ show arg

hx_showtx :: Network -> [BS] -> IO ()
hx_showtx net args = case args of
  [] -> out =<< readTxFile "-"
  [file] -> out =<< readTxFile file
  _ -> error "Usage: hx showtx [<TXFILE>]"
  where
    out = emit . txDetails net

hx_txid :: [BS] -> IO ()
hx_txid args = case args of
  [] -> go "-"
  [f] -> go f
  _ -> error "Usage: hx txid [<TXFILE>]"
  where
    go f = emit . fromText . txHashToHex . txHash =<< readTxFile f

-- | Parse a sighash: all, none or single, optionally followed by
-- +anyonecanpay (or |anyonecanpay, -acp).
parseSigHash :: Network -> BS -> SigHash
parseSigHash net s0 = addFork (base `setAcp` acp)
  where
    s = B8.map toLower s0
    (b, rest) = B8.span (\c -> c /= '+' && c /= '|') s
    acp = rest `elem` ["+anyonecanpay", "|anyonecanpay", "+acp", "|acp"] || (not (BS.null rest) && error ("unknown sighash modifier " ++ show rest))
    base = case b of
      "all" -> sigHashAll
      "none" -> sigHashNone
      "single" -> sigHashSingle
      _ -> error $ "unknown sighash type " ++ show s0 ++ ", expected all, none or single"
    setAcp h True = setAnyoneCanPay h
    setAcp h False = h
    addFork h = if isJust net.sigHashForkId then setForkIdFlag h else h

data SigOpts = SigOpts {soValue :: Maybe Word64, soSegwit :: Bool, soSigHash :: SigHash}

sigOpts :: Network -> [BS] -> (SigOpts, [BS])
sigOpts net args0 = (SigOpts v sw sh, rest)
  where
    (vs, args1) = takeOpt1 ["--value", "-v"] args0
    (shs, args2) = takeOpt1 ["--sighash"] args1
    (sw, rest) = takeFlag ["--segwit", "-w"] args2
    v = parseWord64 "value" <$> vs
    sh = maybe (parseSigHash net "all") (parseSigHash net) shs

sigHashOf :: Network -> SigOpts -> Tx -> Int -> Script -> Hash256
sigHashOf net o tx i script
  | (o.soSegwit || isJust net.sigHashForkId) && isNothing o.soValue =
      error "--value <SATOSHIS> of the spent output is required for SegWit and Bitcoin Cash signatures"
  | o.soSegwit = either error id $ txSigHashForkId net tx script val i o.soSigHash
  | otherwise = either error id $ txSigHash net tx script val i o.soSigHash
  where
    val = fromMaybe 0 o.soValue

-- sign-input FILENAME N SCRIPT_CODE [OPTIONS], private key on stdin
hx_sign_input :: Network -> TxFile -> BS -> BS -> [BS] -> IO ()
hx_sign_input net file index script_code args = do
  tx <- readTxFile file
  let (o, rest) = sigOpts net args
      i = parseInt "input index" index
      script = getHex "script" script_code
  no_args "hx sign-input <TXFILE> <INDEX> <SCRIPT_CODE> [--value SATOSHIS] [--segwit] [--sighash TYPE]" rest (return ())
  interactLn $ \k ->
    let prv = fromWifE net k
        h = sigHashOf net o tx i script
     in encodeHex . encodeTxSig net ctx $ TxSignature (signHash ctx prv.key h) o.soSigHash

-- set-input FILENAME N SIGNATURE_AND_PUBKEY_SCRIPT
hx_set_input :: TxFile -> BS -> BS -> IO ()
hx_set_input file index script = do
  tx <- readTxFile file
  let i = parseInt "input index" index
      si = decodeHex "script" script
  checkIndex tx i
  emit . putTx $ Tx tx.version (updateIndex i tx.inputs (\x -> TxIn x.outpoint si x.sequence)) tx.outputs tx.witness tx.locktime

hx_set_witness :: TxFile -> BS -> [BS] -> IO ()
hx_set_witness file index items = do
  tx <- readTxFile file
  let i = parseInt "input index" index
      n = length tx.inputs
      wit0 = take n (tx.witness ++ repeat [])
      wit = updateIndex i wit0 (const (map (decodeHex "witness item") items))
  checkIndex tx i
  emit . putTx $ Tx tx.version tx.inputs tx.outputs (if all null wit then [] else wit) tx.locktime

checkIndex :: Tx -> Int -> IO ()
checkIndex tx i =
  when (i < 0 || i >= length tx.inputs) $
    error "input index out of range"

hx_validsig :: Network -> TxFile -> BS -> BS -> BS -> [BS] -> IO ()
hx_validsig net file i s sigHex args = do
  tx <- readTxFile file
  let (o0, rest) = sigOpts net args
      idx = parseInt "input index" i
      script = getHex "script" s :: Script
  no_args "hx validsig <TXFILE> <INDEX> <SCRIPT_CODE> <SIGNATURE> [--value SATOSHIS] [--segwit]" rest (return ())
  interactLn $ \p ->
    let pub = getPubKey p
        ok = fromMaybe False $ do
          TxSignature txsig sh <- eitherToMaybe (decodeTxSig net ctx (decodeHex "signature" sigHex))
          let o = o0 {soSigHash = sh}
              h = sigHashOf net o tx idx script
          so <- eitherToMaybe (decodeOutput ctx script)
          let keyOk = case so of
                PayPKHash h160 -> addressHash (pubBytes pub) == h160
                PayPK k -> k.point == pub.point
                _ -> False
          return $ keyOk && verifyHashSig ctx h txsig pub.point
     in Verdict ok

------------------------------------------------------------------------------
-- PSBT (BIP 174 / BIP 370)

readPsbt :: BS -> Psbt
readPsbt s0
  | "70736274ff" `BS.isPrefixOf` B8.map toLower s = either err id . decodePsbt $ decodeHex "PSBT" s
  | otherwise = either err id $ decodePsbtBase64 s
  where
    s = ignoreSpaces s0
    err = error . ("invalid PSBT: " ++)

putPsbt :: Psbt -> BS
putPsbt = encodePsbtBase64

-- | Read a PSBT argument: base64, hex, a file name, or '-' for stdin.
psbtArg :: BS -> IO Psbt
psbtArg "-" = readPsbt <$> BS.getContents
psbtArg a = do
  isFile <- doesFileExist (B8.unpack a)
  if isFile then readPsbt <$> readFileBS a else return (readPsbt a)

psbtArgDefault :: [BS] -> IO Psbt
psbtArgDefault [] = psbtArg "-"
psbtArgDefault [a] = psbtArg a
psbtArgDefault _ = error "Too many arguments"

hx_psbt_create :: [BS] -> IO ()
hx_psbt_create args = do
  tx <- case args of
    [] -> readTxFile "-"
    [f] -> readTxFile f
    _ -> error "Usage: hx psbt-create [<TXFILE>]"
  let stripped = Tx tx.version [TxIn i.outpoint "" i.sequence | i <- tx.inputs] tx.outputs [] tx.locktime
  emit . putPsbt $ psbtOf stripped

updateInput :: Int -> (PsbtMap -> PsbtMap) -> Psbt -> Psbt
updateInput i f p
  | i < 0 || i >= length p.inputs = error "input index out of range"
  | otherwise = Psbt p.version p.unsignedTx p.globals (updateIndex i p.inputs f) p.outputs

hx_psbt_add_utxo :: [BS] -> IO ()
hx_psbt_add_utxo (i : prevFile : rest) = do
  prev <- readTxFile prevFile
  p <- psbtArgDefault rest
  let idx = parseInt "input index" i
      op = (p.unsignedTx.inputs !! idx).outpoint
      vout = fromIntegral op.index
  when (idx < 0 || idx >= length p.unsignedTx.inputs) $ error "input index out of range"
  when (txHash prev /= op.hash) $ error "the previous transaction does not match the input"
  when (vout >= length prev.outputs) $ error "the previous transaction has no such output"
  let out = prev.outputs !! vout
      segwitOut = case outputType out.script of
        t -> t `elem` ["p2wpkh", "p2wsh", "p2tr", "witness_unknown"]
      f = (if segwitOut then insertWitnessUtxo out else id) . insertNonWitnessUtxo prev
  emit . putPsbt $ updateInput idx f p
hx_psbt_add_utxo _ = error "Usage: hx psbt-add-utxo <INDEX> <PREVIOUS-TXFILE> [<PSBT>]"

hx_psbt_add_witness_utxo :: Network -> [BS] -> IO ()
hx_psbt_add_witness_utxo net (i : v : scr : rest) = do
  p <- psbtArgDefault rest
  let script = case eitherToMaybe (evaluateAddr scr) of
        Just bs -> bs
        Nothing -> decodeHex "output script or address" scr
      evaluateAddr a = maybe (Left ()) Right (textToAddr net (toText a) >>= addressToScriptBS ctx . plain)
      out = TxOut (parseWord64 "value" v) script
  emit . putPsbt $ updateInput (parseInt "input index" i) (insertWitnessUtxo out) p
hx_psbt_add_witness_utxo _ _ = error "Usage: hx psbt-add-witness-utxo <INDEX> <VALUE> <SCRIPT|ADDRESS> [<PSBT>]"

signerOf :: Network -> BS -> Signer
signerOf net k0 =
  case xPrvImport net (toText k) of
    Just x -> (xPrvSigner ctx x Nothing) {requirePreviousTx = False}
    Nothing ->
      let prv = fromWifE net k
          s = keySigner ctx prv.key
       in s {requirePreviousTx = False}
  where
    k = ignoreSpaces k0

-- | A Taproot input can only be signed when the PSBT names its internal key.
-- When a WIF key is the internal key of a BIP 86 (key path only) output that
-- an input spends, record it so the input can be signed.
addTapInternalKey :: Network -> BS -> Psbt -> Psbt
addTapInternalKey net k p = case fromWif net (toText (ignoreSpaces k)) of
  Nothing -> p
  Just prv ->
    let pub = derivePublicKey ctx prv
        program = BS.pack [0x51, 0x20] <> taprootOutputBytes pub
        coins = either (const []) id (inputCoins p)
        add m (Just c)
          | c.coin.script == program,
            either (const True) isNothing (inputTapInternalKey ctx m) =
              insertInputTapInternalKey ctx pub.point m
        add m _ = m
     in Psbt p.version p.unsignedTx p.globals (zipWith add p.inputs (coins ++ repeat Nothing)) p.outputs

hx_psbt_sign :: Network -> [BS] -> IO ()
hx_psbt_sign net args = case args of
  (key : rest) -> do
    keys <- mapM keyArg (key : init' rest)
    p <- psbtArgDefault (last' rest)
    let signWith q k = signPsbt net ctx (signerOf net k) (addTapInternalKey net k q)
    signed <- either (error . ("cannot sign: " ++)) return $ foldlM signWith p keys
    emit (putPsbt signed)
  _ -> error "Usage: hx psbt-sign <PRIVKEY|XPRV>... [<PSBT>]"
  where
    -- The last argument is the PSBT when it is not a key.
    isKey a = isJust (fromWif net (toText a)) || isJust (xPrvImport net (toText a)) || a == "-"
    init' xs = if not (null xs) && not (isKey (last xs)) then init xs else xs
    last' xs = [last xs | not (null xs), not (isKey (last xs))]
    keyArg "-" = trim <$> BS.getContents
    keyArg a = return a

hx_psbt_combine :: [BS] -> IO ()
hx_psbt_combine args = case args of
  (a : as@(_ : _)) -> do
    p <- psbtArg a
    ps <- mapM psbtArg as
    emit . putPsbt . either error id $ foldlM combinePsbt p ps
  _ -> error "Usage: hx psbt-combine <PSBT> <PSBT>..."

hx_psbt_finalize :: Network -> [BS] -> IO ()
hx_psbt_finalize net args = do
  p <- psbtArgDefault args
  emit . putPsbt . either (error . ("cannot finalize: " ++)) id $ finalizePsbt net ctx p

hx_psbt_extract :: [BS] -> IO ()
hx_psbt_extract args = do
  p <- psbtArgDefault args
  emit . putTx . either (error . ("cannot extract: " ++)) id $ psbtTransaction p

hx_psbt_decode :: Network -> [BS] -> IO ()
hx_psbt_decode net args = do
  p <- psbtArgDefault args
  let coins = either (const (map (const Nothing) p.inputs)) id (inputCoins p)
      inputV n (m, coin) =
        obj
          [ "index" .: (n :: Int),
            "final" .: (isJust (finalScriptSig m) || either (const False) isJust (finalScriptWitness m)),
            "partial_signatures" .: either (const 0) length (partialSignatures ctx m),
            "taproot_key_signature" .: either (const False) isJust (tapKeySig m),
            "utxo" .: (coinV . (.coin) <$> coin)
          ]
      coinV o =
        obj
          [ "value" .: o.value,
            "type" .: outputType o.script,
            "address" .: (eitherToMaybe (scriptToAddressBS net ctx o.script) >>= addrTextMaybe net),
            "script" .: scriptDetails net o.script
          ]
  emit $
    obj
      [ "id" .: txHashToHex (psbtId p),
        "version" .: (if p.version == Version0 then 0 else 2 :: Int),
        "complete" .: either (const False) (const True) (psbtTransaction p),
        "fee" .: eitherToMaybe (psbtFee p),
        "inputs" .: zipWith inputV [0 ..] (zip p.inputs (coins ++ repeat Nothing)),
        "tx" .: txDetails net p.unsignedTx
      ]

------------------------------------------------------------------------------
-- Scripts

hx_rawscript :: BS -> BS
hx_rawscript = putHex . parseReadP parseScript . B8.unpack

hx_showscript :: Network -> BS -> BS
hx_showscript net = B8.pack . showDoc . prettyScript (isCashNet net) . getHex "script"

------------------------------------------------------------------------------
-- Hashes, MACs and key derivation functions

hx_hmac :: String -> (BS -> BS -> BS) -> [BS] -> BS
hx_hmac _ h [key, input] = encodeHex $ h (decodeHex "hmac key" key) (decodeHex "hmac data" input)
hx_hmac m _ _ = error $ "Usage: hx hmac-" ++ m ++ " <HEX-KEY> [<HEX-INPUT>]"

hmacWith :: forall a. (HashAlgorithm a) => a -> BS -> BS -> BS
hmacWith _ k m = BA.convert (hmac k m :: HMAC a)

hx_PBKDF1 :: (BS -> BS) -> BS -> [BS] -> IO ()
hx_PBKDF1 h m = interactArgs go
  where
    u = "hx " ++ B8.unpack m ++ " [--hex] <PASSWORD> [--hex] <SALT> <COUNT>"
    go args0 =
      let (password, args1) = get_hex_arg "password" u args0
          (salt, args2) = get_hex_arg "salt" u args1
          (count, args3) = get_int_arg "count" u args2
       in no_args u args3 . encodeHex $ iterate h (password <> salt) !! count

hx_PBKDF2 :: (Int -> Int -> BS -> BS -> BS) -> BS -> [BS] -> IO ()
hx_PBKDF2 f m = interactArgs go
  where
    u = "hx " ++ B8.unpack m ++ " [--hex] <PASSWORD> [--hex] <SALT> <COUNT> <LENGTH>"
    go args0 =
      let (password, args1) = get_hex_arg "password" u args0
          (salt, args2) = get_hex_arg "salt" u args1
          (count, args3) = get_int_arg "count" u args2
          (len, args4) = get_int_arg "length" u args3
       in no_args u args4 . encodeHex $ f count len password salt

pbkdf2With :: (PBKDF2.PRF BS) -> Int -> Int -> BS -> BS -> BS
pbkdf2With prf c l = PBKDF2.generate prf (PBKDF2.Parameters c l)

------------------------------------------------------------------------------
-- Elliptic curve maths

getPoint :: BS -> Point
getPoint = either error id . decodePoint . decodeHex "curve point"

putPoint :: Point -> BS
putPoint = encodeHex . encodePoint True

getHexN :: BS -> Integer
getHexN s
  | i < curveN = i
  | otherwise = error $ "Integer not in FieldN: " ++ show i
  where
    i = bytesToInteger (decodeHexBytes "field number modulo N" 32 s)

getHexP :: BS -> Integer
getHexP s
  | i < curveP = i
  | otherwise = error $ "Integer not in FieldP: " ++ show i
  where
    i = bytesToInteger (decodeHexBytes "field number modulo P" 32 s)

putHex32 :: Integer -> BS
putHex32 = encodeHex . integerToBytes32

hx_ec_double :: [BS] -> BS
hx_ec_double [p] = putPoint $ doublePoint (getPoint p)
hx_ec_double _ = error "Usage: hx ec-double [<HEX-POINT>]"

hx_ec_multiply :: [BS] -> BS
hx_ec_multiply [x, p] = putPoint $ mulPoint (getHexN x) (getPoint p)
hx_ec_multiply _ = error "Usage: hx ec-multiply <HEX-FIELDN> <HEX-POINT>"

hx_ec_add :: [BS] -> BS
hx_ec_add [p, q] = putPoint $ addPoint (getPoint p) (getPoint q)
hx_ec_add _ = error "Usage: hx ec-add <HEX-POINT> <HEX-POINT>"

hx_ec_tweak_add :: [BS] -> BS
hx_ec_tweak_add [x, p] = putPoint $ addPoint (mulPoint (getHexN x) curveG) (getPoint p)
hx_ec_tweak_add _ = error "Usage: hx ec-tweak-add <HEX-FIELDN> <HEX-POINT>"

hx_ec_add_modp :: [BS] -> BS
hx_ec_add_modp [x, y] = putHex32 $ (getHexP x + getHexP y) `mod` curveP
hx_ec_add_modp _ = error "Usage: hx ec-add-modp <HEX-FIELDP> <HEX-FIELDP>"

hx_ec_add_modn :: [BS] -> BS
hx_ec_add_modn [x, y] = putHex32 $ (getHexN x + getHexN y) `mod` curveN
hx_ec_add_modn _ = error "Usage: hx ec-add-modn <HEX-FIELDN> <HEX-FIELDN>"

hx_ec_int_modp :: [BS] -> BS
hx_ec_int_modp [x] = putHex32 $ readDigits "integer modulo p in decimal" x `mod` curveP
hx_ec_int_modp _ = error "Usage: hx ec-int-modp [<DECIMAL-INTEGER>]"

hx_ec_int_modn :: [BS] -> BS
hx_ec_int_modn [x] = putHex32 $ readDigits "integer modulo n in decimal" x `mod` curveN
hx_ec_int_modn _ = error "Usage: hx ec-int-modn [<DECIMAL-INTEGER>]"

hx_ec_x :: [BS] -> BS
hx_ec_x [p] = putHex32 . fromMaybe (error "invalid point") . pointX $ getPoint p
hx_ec_x _ = error "Usage: hx ec-x [<HEX-POINT>]"

hx_ec_y :: [BS] -> BS
hx_ec_y [p] = putHex32 . fromMaybe (error "invalid point") . pointY $ getPoint p
hx_ec_y _ = error "Usage: hx ec-y [<HEX-POINT>]"

------------------------------------------------------------------------------
-- Command dispatch

mainArgs :: Network -> [BS] -> IO ()
mainArgs net args0 = case args0 of
  -- Addresses
  ("addr" : args) -> interactLn $ hx_addr net args
  ("validaddr" : args) -> interactArg "hx validaddr [<ADDRESS>]" (hx_validaddr net) args
  ("encode-addr" : args) -> interactLn $ hx_encode_addr net args
  ["decode-addr"] -> interactLn $ hx_decode_addr net
  ("addr-info" : args) -> interactArg "hx addr-info [<ADDRESS>]" (hx_addr_info net) args
  ("addr-convert" : args) -> interactLn $ hx_addr_convert net args
  ("addr-to-script" : args) -> interactArg "hx addr-to-script [<ADDRESS>]" (hx_addr_to_script net) args
  ("script-to-addr" : args) -> interactArg "hx script-to-addr [<SCRIPT>]" (hx_script_to_addr net) args
  ("script-addr" : args) -> interactLn $ hx_script_addr net args
  ("multisig" : args) -> emit $ hx_multisig args
  -- Keys
  ("newkey" : args) -> hx_newkey net args
  ("pubkey" : args) -> interactLn $ hx_pubkey net args
  ["xonly-pubkey"] -> interactLn $ hx_xonly_pubkey net
  ("brainwallet" : args) -> emit $ hx_brainwallet net args
  ["wif-to-secret"] -> interactLn $ hx_wif_to_secret net
  ("secret-to-wif" : args) -> interactLn $ hx_secret_to_wif net args
  ["mini-to-wif"] -> interactLn $ hx_mini_to_wif net
  ["compress"] -> interactLn $ hx_compress net
  ["uncompress"] -> interactLn $ hx_uncompress net
  -- Signatures and messages
  ("verifysig-modn" : args) -> interactArgs hx_verifysig_modn args
  ("signmsg-modn" : args) -> interactArgs (hx_signmsg_modn net) args
  ("sign-hash" : args) -> interactArgs (hx_sign_hash net) args
  ("verify-hash" : args) -> interactArgs hx_verify_hash args
  ("schnorr-sign" : args) -> interactArgs (hx_schnorr_sign net) args
  ("schnorr-verify" : args) -> interactArgs hx_schnorr_verify args
  ("message-sign" : args) -> interactArgs (hx_message_sign net) args
  ("message-verify" : args) -> interactArgs (hx_message_verify net) args
  -- HD wallets
  ["hd-priv"] -> interactLn $ hx_hd_priv net Nothing
  ["hd-priv", i] -> interactLn . hx_hd_priv net $ Just (False, parseWord32 "hd-priv index" i)
  ["hd-priv", "--hard", i] -> interactLn . hx_hd_priv net $ Just (True, parseWord32 "hd-priv index" i)
  ["hd-pub"] -> interactLn $ hx_hd_pub net Nothing
  ["hd-pub", i] -> interactLn . hx_hd_pub net . Just $ parseWord32 "hd-pub index" i
  ["hd-path", p] -> interactLn $ hx_hd_path net p
  ["hd-decode"] -> interactLn $ hx_hd_decode net
  ["hd-to-wif"] -> interactLn $ hx_hd_to_wif net
  ["hd-to-pubkey"] -> interactLn $ hx_hd_to_pubkey net
  ("hd-to-address" : args) -> interactLn $ hx_hd_to_address net args
  -- Mnemonics
  ["bip39-mnemonic"] -> interactLn hx_bip39_mnemonic
  ["bip39-hex"] -> interactLn hx_bip39_hex
  ["bip39-seed"] -> interactLn $ hx_bip39_seed ""
  ["bip39-seed", pass] -> interactLn $ hx_bip39_seed pass
  ("bip39-new" : args) -> hx_bip39_new args
  ("slip39-split" : args) -> hx_slip39_split args
  ("slip39-combine" : args) -> hx_slip39_combine args
  ["rfc1751-key"] -> interactLn hx_rfc1751_key
  ["rfc1751-mnemonic"] -> interactLn hx_rfc1751_mnemonic
  ["mnemonic"] -> interactLn hx_mnemonic
  -- Encodings
  ("btc" : args) -> interactArg "hx btc [<SATOSHIS>]" hx_btc args
  ("satoshi" : args) -> interactArg "hx satoshi [<BTCS>]" hx_satoshi args
  ["base58-encode"] -> interactLn hx_base58_encode
  ["base58-decode"] -> interactLn hx_base58_decode
  ("base58check-encode" : args) -> interactLn $ hx_base58check_encode args
  ("base58check-decode" : args) -> interactLn $ hx_base58check_decode args
  ("bech32-encode" : args) -> interactLn $ hx_bech32_encode args
  ["bech32-decode"] -> interactLn hx_bech32_decode
  ["base64-encode"] -> interactLn base64Encode
  ["base64-decode"] -> BS.interact $ either error id . base64Decode
  ["integer"] -> interactLn $ showB8 . bytesToInteger . decodeHex "input"
  ["hex-encode"] -> interactLn encodeHex
  ["hex-decode"] -> BS.interact $ decodeHex "input"
  ["encode-hex"] {-deprecated-} -> interactLn encodeHex
  ["decode-hex"] {-deprecated-} -> BS.interact $ decodeHex "input"
  -- Hashes
  ["ripemd-hash"] -> interactLn $ encodeHex . hash160BS
  ("ripemd160" : args) -> interactHex "hx ripemd160 [<HEX-INPUT>]" ripemd160BS args
  ("sha256" : args) -> interactHex "hx sha256    [<HEX-INPUT>]" sha256BS args
  ("sha512" : args) -> interactHex "hx sha512    [<HEX-INPUT>]" sha512BS args
  ("sha1" : args) -> interactHex "hx sha1      [<HEX-INPUT>]" sha1BS args
  ("hash256" : args) -> interactHex "hx hash256   [<HEX-INPUT>]" hash256BS args
  ("hash160" : args) -> interactHex "hx hash160   [<HEX-INPUT>]" hash160BS args
  ("tagged-hash" : tag : args) -> interactHex "hx tagged-hash <TAG> [<HEX-INPUT>]" (taggedHashBS tag) args
  ("hmac-sha224" : args) -> interactArgs (hx_hmac "sha224" (hmacWith SHA224)) args
  ("hmac-sha256" : args) -> interactArgs (hx_hmac "sha256" (hmacWith SHA256)) args
  ("hmac-sha384" : args) -> interactArgs (hx_hmac "sha384" (hmacWith SHA384)) args
  ("hmac-sha512" : args) -> interactArgs (hx_hmac "sha512" (hmacWith SHA512)) args
  (arg@"sha1pbkdf1" : args) -> hx_PBKDF1 sha1BS arg args
  (arg@"sha256pbkdf1" : args) -> hx_PBKDF1 sha256BS arg args
  (arg@"sha512pbkdf1" : args) -> hx_PBKDF1 sha512BS arg args
  (arg@"sha1pbkdf2" : args) -> hx_PBKDF2 (pbkdf2With (PBKDF2.prfHMAC SHA1)) arg args
  (arg@"sha256pbkdf2" : args) -> hx_PBKDF2 (pbkdf2With (PBKDF2.prfHMAC SHA256)) arg args
  (arg@"sha512pbkdf2" : args) -> hx_PBKDF2 (pbkdf2With (PBKDF2.prfHMAC SHA512)) arg args
  ("chksum32" : args) -> interactArgs hx_chksum32 args
  ("chksum32-encode" : args) -> interactArgs hx_chksum32_encode args
  ("chksum32-decode" : args) -> interactArgs hx_chksum32_decode args
  -- Elliptic curve
  ("ec-double" : args) -> interactArgs hx_ec_double args
  ("ec-add" : args) -> interactArgs hx_ec_add args
  ("ec-multiply" : args) -> interactArgs hx_ec_multiply args
  ("ec-tweak-add" : args) -> interactArgs hx_ec_tweak_add args
  ("ec-add-modp" : args) -> interactArgs hx_ec_add_modp args
  ("ec-add-modn" : args) -> interactArgs hx_ec_add_modn args
  ["ec-g"] -> emit $ putPoint curveG
  ["ec-p"] -> emit $ putHex32 curveP
  ["ec-n"] -> emit $ putHex32 curveN
  ["ec-a"] -> emit $ putHex32 curveA
  ["ec-b"] -> emit $ putHex32 curveB
  ["ec-inf"] -> emit $ putPoint Infinity
  ("ec-int-modp" : args) -> interactArgs hx_ec_int_modp args
  ("ec-int-modn" : args) -> interactArgs hx_ec_int_modn args
  ("ec-x" : args) -> interactArgs hx_ec_x args
  ("ec-y" : args) -> interactArgs hx_ec_y args
  -- Transactions
  ("mktx" : file : args) -> interactFileArgs (hx_mktx net) file args
  ("showtx" : args) -> hx_showtx net args
  ("txid" : args) -> hx_txid args
  ("sign-input" : f : i : s : args) -> hx_sign_input net f i s args
  ["set-input", f, i, s] -> hx_set_input f i s
  ("set-witness" : f : i : items) -> hx_set_witness f i items
  ("validsig" : f : i : s : sg : args) -> hx_validsig net f i s sg args
  -- PSBT
  ("psbt-create" : args) -> hx_psbt_create args
  ("psbt-decode" : args) -> hx_psbt_decode net args
  ("psbt-add-utxo" : args) -> hx_psbt_add_utxo args
  ("psbt-add-witness-utxo" : args) -> hx_psbt_add_witness_utxo net args
  ("psbt-sign" : args) -> hx_psbt_sign net args
  ("psbt-combine" : args) -> hx_psbt_combine args
  ("psbt-finalize" : args) -> hx_psbt_finalize net args
  ("psbt-extract" : args) -> hx_psbt_extract args
  -- Scripts
  ("rawscript" : args) -> interactArgs (hx_rawscript . B8.unwords) args
  ["showscript"] -> interactLn $ hx_showscript net
  -- Electrum
  ["electrum-mpk"] -> interactLn hx_electrum_mpk
  ("electrum-priv" : args) -> interactLn $ hx_electrum_priv net args
  ("electrum-pub" : args) -> interactLn $ hx_electrum_pub args
  ("electrum-addr" : args) -> interactLn $ hx_electrum_addr net args
  ("electrum-seq" : args) -> interactLn $ hx_electrum_sequence args
  ["electrum-stretch-seed"] -> interactLn hx_electrum_stretch_seed
  -- Misc
  ["networks"] ->
    emit $ List [obj ["name" .: T.pack n, "aliases" .: map T.pack aliases] | (n, aliases) <- networkNames]
  ["help"] -> putStr =<< colorHelp usage
  ["--help"] -> putStr =<< colorHelp usage
  ["-h"] -> putStr =<< colorHelp usage
  ["version"] -> emit ("hx " <> version :: BS)
  ["--version"] -> emit ("hx " <> version :: BS)
  _ -> error $ "Unexpected arguments.\n\n" ++ usage

usage :: String
usage =
  unlines
    [ "Usage: hx [-n|--network NETWORK] [-j|--json] [-y|--yaml] [--color[=WHEN]] COMMAND [ARGS...]",
      "",
      "Results print as YAML, or as JSON with --json (or HX_FORMAT=json); JSON is",
      "compact when the output is not a terminal. Colors are used on terminals;",
      "--color=always|never|auto and NO_COLOR override that. A result that is a",
      "single value prints bare. Verifications print true or false and exit with",
      "status 1 when false.",
      "",
      "Command names are case-insensitive: SHA256 is equivalent to sha256.",
      "NETWORK defaults to $HX_NETWORK or btc. See `hx networks`.",
      "Arguments shown as [<ARG>] are read from standard input when omitted;",
      "a single '-' argument also reads standard input.",
      "",
      "# ADDRESSES",
      "hx addr [--type p2pkh|p2wpkh|p2sh-p2wpkh|p2tr]   (key on stdin)",
      "hx validaddr [<ADDRESS>]",
      "hx decode-addr",
      "hx encode-addr [--p2pkh|--p2sh|--p2wpkh|--p2wsh|--p2tr|--p2sh32|--token-p2pkh|--token-p2sh]",
      "hx addr-info [<ADDRESS>]",
      "hx addr-convert --to legacy|cashaddr|token",
      "hx addr-to-script [<ADDRESS>]",
      "hx script-to-addr [<SCRIPT>]",
      "hx script-addr [--p2sh|--p2wsh|--p2sh-p2wsh|--p2sh32]",
      "hx multisig [--sort] <M> <PUBKEY>...",
      "",
      "# KEYS",
      "hx newkey [--uncompressed]",
      "hx pubkey [--compressed|--uncompressed]",
      "hx xonly-pubkey",
      "hx wif-to-secret",
      "hx secret-to-wif [--uncompressed]",
      "hx mini-to-wif",
      "hx brainwallet <PASSPHRASE>",
      "hx compress",
      "hx uncompress",
      "",
      "# SIGNATURES AND MESSAGES",
      "hx message-sign [--type p2pkh|p2wpkh|p2sh-p2wpkh] <PRIVKEY> <MESSAGE>",
      "hx message-verify <ADDRESS> <SIGNATURE> <MESSAGE>",
      "hx sign-hash <PRIVKEY> <HEX-HASH32>",
      "hx verify-hash <PUBKEY> <DER-SIGNATURE> <HEX-HASH32>",
      "hx schnorr-sign <PRIVKEY> <HEX-MESSAGE32>",
      "hx schnorr-verify <XONLY-PUBKEY> <SIGNATURE> <HEX-MESSAGE32>",
      "hx signmsg-modn <MESSAGE-DECIMAL-INTEGER> <PRIVKEY>",
      "hx verifysig-modn <MESSAGE-DECIMAL-INTEGER> <PUBKEY> <SIGNATURE>",
      "",
      "# SCRIPTS",
      "hx rawscript <SCRIPT_OP>*",
      "hx showscript",
      "",
      "# TRANSACTIONS",
      "hx mktx <TXFILE> --input <TXID>:<INDEX>... --output <ADDR>:<SATOSHIS>...",
      "        [--data <HEX>] [--version N] [--locktime N] [--sequence N] [--rbf]",
      "hx showtx [<TXFILE>]",
      "hx txid [<TXFILE>]",
      "hx sign-input <TXFILE> <INDEX> <SCRIPT_CODE> [--value SATOSHIS] [--segwit] [--sighash TYPE]",
      "hx set-input <TXFILE> <INDEX> <SCRIPT>",
      "hx set-witness <TXFILE> <INDEX> <HEX-ITEM>...",
      "hx validsig <TXFILE> <INDEX> <SCRIPT_CODE> <SIGNATURE> [--value SATOSHIS] [--segwit]",
      "",
      "# PARTIALLY SIGNED TRANSACTIONS (BIP174)",
      "hx psbt-create [<TXFILE>]",
      "hx psbt-decode [<PSBT>]",
      "hx psbt-add-utxo <INDEX> <PREVIOUS-TXFILE> [<PSBT>]",
      "hx psbt-add-witness-utxo <INDEX> <SATOSHIS> <SCRIPT|ADDRESS> [<PSBT>]",
      "hx psbt-sign <PRIVKEY|XPRV>... [<PSBT>]",
      "hx psbt-combine <PSBT> <PSBT>...",
      "hx psbt-finalize [<PSBT>]",
      "hx psbt-extract [<PSBT>]",
      "",
      "# HD WALLET (BIP32)",
      "hx hd-priv",
      "hx hd-priv <INDEX>",
      "hx hd-priv --hard <INDEX>",
      "hx hd-pub",
      "hx hd-pub <INDEX>",
      "hx hd-path <PATH>",
      "hx hd-decode",
      "hx hd-to-wif",
      "hx hd-to-address [--type p2pkh|p2wpkh|p2sh-p2wpkh|p2tr]",
      "hx hd-to-pubkey",
      "",
      "# ELECTRUM DETERMINISTIC WALLET (legacy)",
      "hx electrum-mpk",
      "hx electrum-priv <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]",
      "hx electrum-pub  <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]",
      "hx electrum-addr <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]",
      "hx electrum-seq  <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]",
      "hx electrum-stretch-seed",
      "",
      "# ELLIPTIC CURVE MATHS",
      "hx ec-multiply  <HEX-FIELDN> <HEX-POINT>",
      "hx ec-tweak-add <HEX-FIELDN> <HEX-POINT>",
      "hx ec-add-modp  <HEX-FIELDP> <HEX-FIELDP>",
      "hx ec-add-modn  <HEX-FIELDN> <HEX-FIELDN>",
      "hx ec-add       <HEX-POINT>  <HEX-POINT>",
      "hx ec-double    <HEX-POINT>",
      "hx ec-g | ec-p | ec-n | ec-a | ec-b | ec-inf",
      "hx ec-int-modp <DECIMAL-INTEGER>",
      "hx ec-int-modn <DECIMAL-INTEGER>",
      "hx ec-x <HEX-POINT>",
      "hx ec-y <HEX-POINT>",
      "",
      "# MNEMONICS AND SEED FORMATS",
      "hx bip39-new [<12|15|18|21|24>]",
      "hx bip39-mnemonic",
      "hx bip39-hex",
      "hx bip39-seed [<PASSPHRASE>]",
      "hx slip39-split <THRESHOLD> <SHARES> [<PASSPHRASE>]",
      "hx slip39-combine [<PASSPHRASE>]",
      "hx mnemonic",
      "hx rfc1751-key",
      "hx rfc1751-mnemonic",
      "",
      "# BASIC ENCODINGS AND CONVERSIONS",
      "hx btc [<SATOSHIS>]",
      "hx satoshi [<BTCS>]",
      "hx integer",
      "hx hex-encode",
      "hx hex-decode",
      "hx base64-encode",
      "hx base64-decode",
      "hx base58-encode",
      "hx base58-decode",
      "hx base58check-encode [<VERSION-BYTE>]",
      "hx base58check-decode",
      "hx bech32-encode [--m] <HRP>",
      "hx bech32-decode",
      "",
      "# CHECKSUM32 (first 32bits of double sha256)",
      "hx chksum32 <HEX>*",
      "hx chksum32-encode <HEX>*",
      "hx chksum32-decode <HEX>*",
      "",
      "# HASHING",
      "hx ripemd-hash                 (raw input)",
      "hx sha1       [<HEX-INPUT>]",
      "hx sha256     [<HEX-INPUT>]",
      "hx sha512     [<HEX-INPUT>]",
      "hx ripemd160  [<HEX-INPUT>]",
      "hx hash160    [<HEX-INPUT>]",
      "hx hash256    [<HEX-INPUT>]",
      "hx tagged-hash <TAG> [<HEX-INPUT>]",
      "",
      "# HASH BASED MACs",
      "hx hmac-sha224 <HEX-KEY> [<HEX-INPUT>]",
      "hx hmac-sha256 <HEX-KEY> [<HEX-INPUT>]",
      "hx hmac-sha384 <HEX-KEY> [<HEX-INPUT>]",
      "hx hmac-sha512 <HEX-KEY> [<HEX-INPUT>]",
      "",
      "# PASSWORD BASED KEY DERIVATION FUNCTIONS",
      "hx sha1pbkdf1   [--hex] <PASSWORD> [--hex] <SALT> <COUNT>",
      "hx sha256pbkdf1 [--hex] <PASSWORD> [--hex] <SALT> <COUNT>",
      "hx sha512pbkdf1 [--hex] <PASSWORD> [--hex] <SALT> <COUNT>",
      "hx sha1pbkdf2   [--hex] <PASSWORD> [--hex] <SALT> <COUNT> <LENGTH>",
      "hx sha256pbkdf2 [--hex] <PASSWORD> [--hex] <SALT> <COUNT> <LENGTH>",
      "hx sha512pbkdf2 [--hex] <PASSWORD> [--hex] <SALT> <COUNT> <LENGTH>",
      "",
      "# MISC",
      "hx networks",
      "hx help",
      "hx version",
      "",
      "PATH      ::= <PATH-HEAD> <PATH-CONT>",
      "PATH-HEAD ::= 'm'   [extended private key]",
      "            | 'M'   [extended public  key]",
      "            | 'p'   [private key (compressed WIF)]",
      "            | 'u'   [private key (uncompressed WIF)]",
      "            | 'P'   [public key (compressed)]",
      "            | 'U'   [public key (uncompressed)]",
      "            | 'X'   [public key (x-only, BIP340)]",
      "            | 'A'   [AddrP2PKH address (CashAddr on Bitcoin Cash)]",
      "            | 'W'   [AddrP2WPKH address]",
      "            | 'S'   [P2SH-AddrP2WPKH address]",
      "            | 'T'   [AddrP2TR address (BIP86)]",
      "PATH-CONT ::=                                [empty]",
      "            | '/' <INDEX> <PATH-CONT>        [child key]",
      "            | '/' <INDEX> '\\'' <PATH-CONT>  [hardened child key, also h or H]"
    ]

------------------------------------------------------------------------------
-- Entry point

version :: BS
version = "0.3.0.0"

data Opts = Opts
  { optNetwork :: Maybe String,
    optJson :: Maybe Bool,
    optColor :: ColorWhen
  }

-- | Extract the global options. The network and the short options must
-- precede the command; the long output options are accepted anywhere.
-- A later occurrence wins.
globalOpts :: [String] -> (Opts, [String])
globalOpts = lead (Opts Nothing Nothing ColorAuto)
  where
    lead o (f : v : rest) | f `elem` ["-n", "--network"] = lead o {optNetwork = Just v} rest
    lead o (f : rest) | Just v <- stripPrefix "--network=" f = lead o {optNetwork = Just v} rest
    lead o ("-j" : rest) = lead o {optJson = Just True} rest
    lead o ("-y" : rest) = lead o {optJson = Just False} rest
    lead o (f : rest) | Just o' <- long o f = lead o' rest
    lead o rest = anywhere o rest
    anywhere o (f : rest)
      | Just o' <- long o f = anywhere o' rest
      | otherwise = let (o'', r) = anywhere o rest in (o'', f : r)
    anywhere o [] = (o, [])
    long o f = case f of
      "--json" -> Just o {optJson = Just True}
      "--yaml" -> Just o {optJson = Just False}
      "--no-color" -> Just o {optColor = ColorNever}
      "--color" -> Just o {optColor = ColorAlways}
      "--color=always" -> Just o {optColor = ColorAlways}
      "--color=never" -> Just o {optColor = ColorNever}
      "--color=auto" -> Just o {optColor = ColorAuto}
      _
        | Just w <- stripPrefix "--color=" f -> error $ "--color expects always, never or auto, not " ++ show w
        | otherwise -> Nothing

reportError :: SomeException -> IO a
reportError e
  | Just (ec :: ExitCode) <- fromException e = throwIO ec
  | Just (ErrorCall m) <- fromException e = die' m
  | Just (ioe :: IOException) <- fromException e = die' (show ioe)
  | otherwise = die' (displayException e)
  where
    die' m = do
      prefix <- errorPrefix
      hPutStrLn stderr (T.unpack prefix ++ " " ++ m)
      exitWith (ExitFailure 1)

main :: IO ()
main = handle reportError $ do
  args <- getArgs
  envNet <- lookupEnv "HX_NETWORK"
  envFormat <- lookupEnv "HX_FORMAT"
  let (opts, rest) = globalOpts args
      net = parseNetwork (fromMaybe "btc" (optNetwork opts <|> envNet))
      json = case optJson opts of
        Just j -> j
        Nothing -> case map toLower <$> envFormat of
          Just "json" -> True
          Just "yaml" -> False
          Nothing -> False
          Just f -> error $ "HX_FORMAT must be yaml or json, not " ++ show f
  setStyle =<< detectStyle json (optColor opts)
  _ <- evaluate net
  mainArgs net (toLowerFirst (map B8.pack rest))
  where
    toLowerFirst [] = []
    toLowerFirst (x : xs) = B8.map toLower x : xs
