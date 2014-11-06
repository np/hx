{-# LANGUAGE OverloadedStrings #-}
module DetailedTx where

import Data.Aeson hiding (decode')
import qualified Data.ByteString.Lazy as LBS

import Network.Haskoin.Crypto (txHash)
import Network.Haskoin.Internals (Tx(..), TxIn(..), TxOut(..)
                                 ,scriptSender, scriptRecipient
                                 )
import Network.Haskoin.Util (eitherToMaybe,decode')

import PrettyScript (showDoc, prettyScript)

newtype DetailedTx    = DetailedTx    { _unDetailedTx    :: Tx    }
newtype DetailedTxIn  = DetailedTxIn  { _unDetailedTxIn  :: TxIn  }
newtype DetailedTxOut = DetailedTxOut { _unDetailedTxOut :: TxOut }

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

txDetailedJSON :: Tx -> LBS.ByteString
txDetailedJSON = encode . toJSON . DetailedTx
