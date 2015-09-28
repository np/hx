{-# LANGUAGE OverloadedStrings #-}
module DetailedTx where

import Data.Aeson hiding (decode')
import Data.Aeson.Types (Pair)
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text as T

import Network.Haskoin.Crypto (pubKeyAddr,addrToBase58,derivePubKey,toWif)
import Network.Haskoin.Transaction (txHash)
import Network.Haskoin.Internals (Tx(..), TxIn(..), TxOut(..)
                                 ,scriptSender, scriptRecipient
                                 ,XPrvKey(..),XPubKey(..)
                                 ,xPrvIsHard,xPrvChild,xPubIsHard,xPubChild
                                 )
import Network.Haskoin.Util (eitherToMaybe,decode')
import Utils (putHex)

import PrettyScript (showDoc, prettyScript)

(.=$) :: T.Text -> String -> Pair
(.=$) x y = x .= y

newtype DetailedTx    = DetailedTx    { _unDetailedTx    :: Tx    }
newtype DetailedTxIn  = DetailedTxIn  { _unDetailedTxIn  :: TxIn  }
newtype DetailedTxOut = DetailedTxOut { _unDetailedTxOut :: TxOut }
newtype DetailedXPrvKey = DetailedXPrvKey { _unDetailedXPrvKey :: XPrvKey }
newtype DetailedXPubKey = DetailedXPubKey { _unDetailedXPubKey :: XPubKey }

instance ToJSON DetailedTx where
  toJSON (DetailedTx tx) =
    object
      ["hash"     .= txHash tx
      ,"version"  .= txVersion tx
      ,"locktime" .= txLockTime tx
      ,"inputs"   .= map DetailedTxIn  (txIn  tx)
      ,"outputs"  .= map DetailedTxOut (txOut tx)
      ]

instance ToJSON DetailedTxIn where
  toJSON (DetailedTxIn i) =
    object
      ["previous_output" .= prevOutput i
      ,"script"          .= showDoc (prettyScript script)
      ,"sequence"        .= txInSequence i
      ,"address"         .= eitherToMaybe (scriptSender script)
      ]
    where script = decode' $ scriptInput i

instance ToJSON DetailedTxOut where
  toJSON (DetailedTxOut o) =
    object
      ["value"   .= outValue o
      ,"script"  .= showDoc (prettyScript script)
      ,"address" .= eitherToMaybe (scriptRecipient script)
      ]
    where script = decode' $ scriptOutput o

instance ToJSON DetailedXPrvKey where
  toJSON (DetailedXPrvKey k) =
    object
      ["type"    .=$ "xprv"
      ,"depth"   .=  xPrvDepth k
      ,"parent"  .=  xPrvParent k
      ,"index"   .=  object ["value" .= xPrvIndex k
                            ,(if xPrvIsHard k then "hard" else "soft") .= xPrvChild k
                            ]
      ,"chain"   .=  xPrvChain k
      ,"prvkey"  .=  toWif (xPrvKey k)
      ,"pubkey"  .=$ putHex pub
      ,"address" .=  addrToBase58 addr
      ]
   where pub  = derivePubKey (xPrvKey k)
         addr = pubKeyAddr pub

instance ToJSON DetailedXPubKey where
  toJSON (DetailedXPubKey k) =
    object
      ["type"    .=$ "xpub"
      ,"depth"   .=  xPubDepth k
      ,"parent"  .=  xPubParent k
      ,"index"   .=  object ["value" .= xPubIndex k
                            ,(if xPubIsHard k then "hard" else "soft") .= xPubChild k
                            ]
      ,"chain"   .=  xPubChain k
      ,"pubkey"  .=$ putHex pub
      ,"address" .=  addrToBase58 addr
      ]
   where pub  = xPubKey k
         addr = pubKeyAddr pub

txDetailedJSON :: Tx -> LBS.ByteString
txDetailedJSON = encode . toJSON . DetailedTx
