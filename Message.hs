{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Bitcoin signed messages, as produced by Bitcoin Core @signmessage@,
-- Electrum and Electron Cash, with the BIP 137 header bytes that tell
-- which kind of address signed.
module Message
  ( messageHash,
    signMessage,
    verifyMessage,
    base64Encode,
    base64Decode,
  )
where

import Context (ctx)
import Crypto.Secp256k1
import Crypto.Secp256k1.Recovery
import Data.Bits (shiftR, (.&.))
import Data.ByteArray.Encoding (Base (Base64), convertFromBase, convertToBase)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import Haskoin (Address, PrivateKey (..), PublicKey (..))
import Keys
import Utils

base64Encode :: BS -> BS
base64Encode = convertToBase Base64

base64Decode :: BS -> Either String BS
base64Decode = convertFromBase Base64 . ignoreSpaces

varInt :: Int -> BS
varInt n
  | n < 0xfd = BS.singleton (fromIntegral n)
  | n <= 0xffff = BS.cons 0xfd (le 2)
  | n <= 0xffffffff = BS.cons 0xfe (le 4)
  | otherwise = BS.cons 0xff (le 8)
  where
    le k = BS.pack [fromIntegral (n `shiftR` (8 * i)) | i <- [0 .. k - 1]]

-- | Double SHA256 of the message with the "Bitcoin Signed Message" prefix.
-- Bitcoin Cash wallets (Electron Cash, Bitcoin Cash Node) use the same prefix.
messageHash :: BS -> BS
messageHash m =
  hash256BS $ varInt (BS.length magic) <> magic <> varInt (BS.length m) <> m
  where
    magic = "Bitcoin Signed Message:\n"

headerBase :: AddrType -> Bool -> Word8
headerBase AddrP2PKH False = 27
headerBase AddrP2PKH True = 31
headerBase AddrP2SH_P2WPKH _ = 35
headerBase AddrP2WPKH _ = 39
headerBase AddrP2TR _ = error "Taproot addresses cannot sign messages with this scheme (see BIP 322)"

-- | Sign a message. The result is the Base64 encoding of the 65-byte
-- recoverable signature.
signMessage :: AddrType -> PrivateKey -> BS -> BS
signMessage ty prv m
  | ty /= AddrP2PKH && not prv.compress =
      error "SegWit addresses require a compressed private key"
  | otherwise = base64Encode $ BS.cons (headerBase ty prv.compress + recId) sigBytes
  where
    digest = maybe (error "invalid message hash") id $ msg (messageHash m)
    (compact, recId) = exportCompactRecSig ctx (signRecMsg ctx prv.key digest)
    sigBytes = compact.get

-- | Verify a signed message against an address. A signature made by a
-- AddrP2PKH, P2SH-AddrP2WPKH or AddrP2WPKH key is accepted for any of the three
-- addresses of that key, as Electrum and Trezor do.
verifyMessage :: Address -> BS -> BS -> Either String Bool
verifyMessage addr sig64 m = do
  raw <- base64Decode sig64
  (h, compactBytes) <- maybe (Left "empty signature") Right (BS.uncons raw)
  if BS.length compactBytes /= 64 || h < 27 || h > 42
    then Left "invalid signature encoding"
    else do
      let recId = (h - 27) .&. 3
          compressed = h >= 31
      compact <- maybe (Left "invalid signature") Right (compactSig compactBytes)
      rs <- maybe (Left "invalid signature") Right (importCompactRecSig ctx compact recId)
      digest <- maybe (Left "invalid message hash") Right (msg (messageHash m))
      case recover ctx rs digest of
        Nothing -> return False
        Just pk -> do
          let pub = PublicKey pk compressed
              types = if compressed then [AddrP2PKH, AddrP2SH_P2WPKH, AddrP2WPKH] else [AddrP2PKH]
          return $ addr `elem` map (`addrOfPub` pub) types
