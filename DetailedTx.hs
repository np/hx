{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Structured descriptions of transactions and extended keys.
module DetailedTx
  ( txDetails,
    xPrvDetails,
    xPubDetails,
    outputType,
    scriptDetails,
    addressesOf,
  )
where

import Context (ctx)
import qualified Data.ByteString as BS
import Data.Bytes.Get (runGetS)
import Data.Bytes.Serial (deserialize)
import Data.Maybe (catMaybes)
import Data.Text (Text)
import qualified Data.Text as T
import Haskoin hiding (decodeHex, encodeHex)
import Keys
import Output
import PrettyScript (prettyScript, showDoc)
import Utils

decodeScriptE :: BS -> Either String Script
decodeScriptE = runGetS deserialize

-- | A script as assembly and hexadecimal.
scriptDetails :: Network -> BS -> Val
scriptDetails net bs =
  obj
    [ "asm" .: case decodeScriptE bs of
        Right s -> T.pack (showDoc (prettyScript (isCashNet net) s))
        Left _ -> "<unparsable script>",
      "hex" .: encodeHex bs
    ]

-- | Drop the fields whose value is null.
present :: [(Text, Val)] -> [(Text, Val)]
present = filter ((/= Null) . snd)

addrV :: Network -> Maybe Address -> Val
addrV net ma = toVal (ma >>= addrTextMaybe net)

txDetails :: Network -> Tx -> Val
txDetails net tx =
  obj
    [ "txid" .: txHashToHex (txHash tx),
      "wtxid" .: txHashToHex (txWitnessHash tx),
      "version" .: tx.version,
      "locktime" .: tx.locktime,
      "rbf" .: any ((< 0xfffffffe) . (.sequence)) tx.inputs,
      "size" .: BS.length (encodeS tx),
      "vsize" .: txVirtualSize tx,
      "weight" .: txWeight tx,
      "value_out" .: sum (map (toInteger . (.value)) tx.outputs),
      "inputs" .: zipWith (txInDetails net) tx.inputs witnesses,
      "outputs" .: zipWith (txOutDetails net) [0 :: Int ..] tx.outputs
    ]
  where
    witnesses = tx.witness ++ repeat []

txInDetails :: Network -> TxIn -> WitnessStack -> Val
txInDetails net i wit =
  obj . present $
    [ "outpoint" .: (txHashToHex i.outpoint.hash <> ":" <> T.pack (show i.outpoint.index)),
      "sequence" .: i.sequence,
      "address" .: addrV net (inputAddr net i.script wit)
    ]
      ++ ["script" .: scriptDetails net i.script | not (BS.null i.script)]
      ++ ["witness" .: map encodeHex wit | not (null wit)]

-- | Guess the address an input spends from its script and witness.
inputAddr :: Network -> BS -> WitnessStack -> Maybe Address
inputAddr net script wit
  -- P2WPKH: empty script, witness [signature, compressed public key]
  | BS.null script, [_, pk] <- wit, BS.length pk == 33 = do
      pub <- eitherToMaybe (unmarshal ctx pk)
      pubKeyWitnessAddr ctx pub
  -- P2TR key path spend, or an unsigned input
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

txOutDetails :: Network -> Int -> TxOut -> Val
txOutDetails net n o =
  obj . present $
    [ "index" .: n,
      "value" .: o.value,
      "type" .: outputType o.script,
      "address" .: addrV net (eitherToMaybe (scriptToAddressBS net ctx o.script)),
      "script" .: scriptDetails net o.script
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

-- | Addresses of a public key, by type, for the network.
addressesOf :: Network -> PublicKey -> Val
addressesOf net pub =
  obj $
    catMaybes
      [ (key .:) <$> addrTextMaybe net (addrOfPub ty pub)
      | (key, ty) <-
          [ ("p2pkh", AddrP2PKH),
            ("p2wpkh", AddrP2WPKH),
            ("p2sh-p2wpkh", AddrP2SH_P2WPKH),
            ("p2tr", AddrP2TR)
          ],
        pub.compress || ty == AddrP2PKH
      ]

xKeyPairs :: Network -> XPubKey -> [(Text, Val)]
xKeyPairs net k =
  [ "network" .: T.pack net.name,
    "depth" .: k.depth,
    "index" .: xPubChild k,
    "hardened" .: xPubIsHard k,
    "fingerprint" .: fingerprintToText (xPubFP ctx k),
    "parent_fingerprint" .: fingerprintToText k.parent,
    "chain_code" .: encodeHex (encodeS k.chain)
  ]

xPrvDetails :: Network -> XPrvKey -> Val
xPrvDetails net k =
  obj $
    ("type" .: ("xprv" :: Text))
      : xKeyPairs net pub
      ++ [ "xprv" .: xPrvExport net k,
           "xpub" .: xPubExport net ctx pub,
           "wif" .: xPrvWif net k,
           "pubkey" .: putPubKey (wrapPubKey True pub.key),
           "addresses" .: addressesOf net (wrapPubKey True pub.key)
         ]
  where
    pub = deriveXPubKey ctx k

xPubDetails :: Network -> XPubKey -> Val
xPubDetails net k =
  obj $
    ("type" .: ("xpub" :: Text))
      : xKeyPairs net k
      ++ [ "xpub" .: xPubExport net ctx k,
           "pubkey" .: putPubKey (wrapPubKey True k.key),
           "addresses" .: addressesOf net (wrapPubKey True k.key)
         ]
