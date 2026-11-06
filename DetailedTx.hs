{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- | JSON descriptions of transactions and extended keys.
module DetailedTx
  ( txDetailedJSON,
    txDetailedValue,
    xPrvDetails,
    xPubDetails,
    outputType,
  )
where

import Context (ctx)
import Data.Aeson
import Data.Aeson.Types (Pair)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Bytes.Get (runGetS)
import Data.Bytes.Serial (deserialize)
import Data.Maybe (catMaybes)
import Data.Text (Text)
import Data.Word (Word32)
import EC (bytesToInteger)
import Haskoin hiding (decodeHex, encodeHex)
import Keys
import PrettyScript (prettyScript, showDoc)
import Utils

hexT :: BS -> Value
hexT = toJSON . toText . encodeHex

prettyT :: Network -> BS -> Value
prettyT net bs = case decodeScriptE bs of
  Right s -> toJSON (showDoc (prettyScript (isCashNet net) s))
  Left _ -> toJSON ("<unparsable script>" :: Text)

decodeScriptE :: BS -> Either String Script
decodeScriptE = runGetS deserialize

addrT :: Network -> Maybe Address -> Value
addrT net ma = toJSON (toText <$> (ma >>= addrTextMaybe net))

txDetailedValue :: Network -> Tx -> Value
txDetailedValue net tx =
  object
    [ "hash" .= txHashToHex (txHash tx),
      "txid" .= txHashToHex (txHash tx),
      "wtxid" .= txHashToHex (txWitnessHash tx),
      "version" .= tx.version,
      "locktime" .= tx.locktime,
      "size" .= BS.length (encodeS tx),
      "vsize" .= txVirtualSize tx,
      "weight" .= txWeight tx,
      "inputs" .= zipWith (detailedTxIn net) tx.inputs witnesses,
      "outputs" .= map (detailedTxOut net) tx.outputs
    ]
  where
    witnesses = tx.witness ++ repeat []

detailedTxIn :: Network -> TxIn -> WitnessStack -> Value
detailedTxIn net i wit =
  object $
    [ "previous_output" .= toText (putHex i.outpoint),
      "txid" .= txHashToHex i.outpoint.hash,
      "index" .= i.outpoint.index,
      "script" .= prettyT net i.script,
      "script_hex" .= hexT i.script,
      "sequence" .= i.sequence,
      "address" .= addrT net (inputAddr net i.script wit)
    ]
      ++ ["witness" .= map hexT wit | not (null wit)]

-- | Guess the address an input spends from its script and witness.
inputAddr :: Network -> BS -> WitnessStack -> Maybe Address
inputAddr net script wit
  -- AddrP2WPKH: empty script, witness [signature, compressed public key]
  | BS.null script, [_, pk] <- wit, BS.length pk == 33 = do
      pub <- eitherToMaybe (unmarshal ctx pk)
      pubKeyWitnessAddr ctx pub
  -- AddrP2TR key path spend
  | BS.null script = Nothing
  | otherwise = do
      s <- eitherToMaybe (decodeScriptE script)
      case eitherToMaybe (decodeInput net ctx s) >>= inputAddress ctx of
        Just a -> Just a
        -- Old transactions may carry signatures that are not strictly
        -- encoded, which decodeInput rejects. Fall back on the shape of a
        -- pay-to-public-key-hash spend: a signature and a public key.
        Nothing -> case s.ops of
          [OP_PUSHDATA _ _, OP_PUSHDATA pk _] ->
            pubKeyAddr ctx <$> eitherToMaybe (unmarshal ctx pk)
          _ -> Nothing

detailedTxOut :: Network -> TxOut -> Value
detailedTxOut net o =
  object
    [ "value" .= o.value,
      "script" .= prettyT net o.script,
      "script_hex" .= hexT o.script,
      "type" .= outputType o.script,
      "address" .= addrT net (eitherToMaybe (scriptToAddressBS net ctx o.script))
    ]

-- | A short name for the kind of output script.
outputType :: BS -> Text
outputType bs = case decodeScriptE bs >>= decodeOutput ctx of
  Right PayPK {} -> "p2pk"
  Right PayPKHash {} -> "p2pkh"
  Right PayMulSig {} -> "multisig"
  Right PayScriptHash {} -> "p2sh"
  Right PayWitnessPKHash {} -> "p2wpkh"
  Right PayWitnessScriptHash {} -> "p2wsh"
  Right (PayWitness 1 p) | BS.length p == 32 -> "p2tr"
  Right PayWitness {} -> "witness_unknown"
  Right PayScript32Hash {} -> "p2sh32"
  Right DataCarrier {} -> "nulldata"
  Left _ -> "nonstandard"

txDetailedJSON :: Network -> Tx -> LBS.ByteString
txDetailedJSON net = encode . txDetailedValue net

indexValue :: Bool -> KeyIndex -> KeyIndex -> Value
indexValue hard child raw =
  object ["value" .= raw, (if hard then "hard" else "soft") .= child]

-- | Addresses of a public key, by type, for the network.
addressesOf :: Network -> PublicKey -> [Pair]
addressesOf net pub =
  [ "addresses"
      .= object
        ( catMaybes
            [ (key .=) . toText <$> addrTextMaybe net a
            | (key, ty) <-
                [ ("p2pkh", AddrP2PKH),
                  ("p2wpkh", AddrP2WPKH),
                  ("p2sh-p2wpkh", AddrP2SH_P2WPKH),
                  ("p2tr", AddrP2TR)
                ],
              let a = addrOfPub ty pub
            ]
        )
  ]

xPubPairs :: Network -> XPubKey -> [Pair]
xPubPairs net k =
  [ "depth" .= k.depth,
    "parent" .= (fromInteger (bytesToInteger (encodeS k.parent)) :: Word32),
    "parent_fingerprint" .= fingerprintToText k.parent,
    "fingerprint" .= fingerprintToText (xPubFP ctx k),
    "index" .= indexValue (xPubIsHard k) (xPubChild k) k.index,
    "chain" .= toText (encodeHex (encodeS k.chain)),
    "pubkey" .= toText (putPubKey pub),
    "address" .= toText (addrText net (pubKeyAddr ctx pub)),
    "xpub" .= xPubExport net ctx k
  ]
    ++ addressesOf net pub
  where
    pub = wrapPubKey True k.key

xPrvDetails :: Network -> XPrvKey -> Value
xPrvDetails net k =
  object $
    ["type" .= ("xprv" :: Text), "prvkey" .= xPrvWif net k, "xprv" .= xPrvExport net k]
      ++ xPubPairs net (deriveXPubKey ctx k)

xPubDetails :: Network -> XPubKey -> Value
xPubDetails net k = object $ ("type" .= ("xpub" :: Text)) : xPubPairs net k
