{-# LANGUAGE OverloadedStrings #-}
module Electrum where

import Data.Word
import Data.Monoid
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8

import Network.Haskoin.Crypto
import Network.Haskoin.Internals (FieldN, Point, curveG, addPoint, mulPoint)
import Network.Haskoin.Util
import Utils

data    El_seed = El_seed { seed_bytes :: BS, stretched_seed_bytes :: BS }
newtype El_mpk  = El_mpk  { mpk_bytes  :: BS }

stretched_seedN :: El_seed -> FieldN
stretched_seedN
  = fromInteger . bsToInteger . stretched_seed_bytes

-- Electrum sequence number used to derived private keys
-- The mpk is given raw (not hex encoded).
sequenceBS :: Word32 -> Bool -> El_mpk -> BS
sequenceBS n for_change mpk =
  hash256BS . hash256BS $
    showB8 n <> ":" <> show01 for_change <> ":" <> mpk_bytes mpk

sequenceN :: Word32 -> Bool -> El_mpk -> FieldN
sequenceN n c = runGet' getFieldN . sequenceBS n c

point_mpk :: El_mpk -> Point
point_mpk = pubKeyPoint . decode' . BS.cons 0x04 . mpk_bytes

mpk_from_secret :: FieldN -> El_mpk
mpk_from_secret = El_mpk . BS.drop 1 . encode' . derivePubKey . PrvKeyU

derived_mpk :: El_seed -> El_mpk
derived_mpk = mpk_from_secret . stretched_seedN

stretch_seed :: BS -> El_seed
stretch_seed seed
  = El_seed seed $ iterate (hash256BS . (<> seedH)) seedH !! 100000
    where seedH = encodeHex seed

decode_seed :: Hex s => s -> El_seed
decode_seed = stretch_seed . decodeHexBytes "electrum seed" 16

decode_mpk :: BS -> El_mpk
decode_mpk s0
  | BS.length s == 32 = derived_mpk . decode_seed $ s
  | otherwise         = El_mpk . decodeHexBytes "electrum master public key" 64 $ s
  where s = ignoreSpaces s0

derive_priv :: Word32 -> Bool -> El_seed -> PrvKey
derive_priv n for_change seed = PrvKeyU sk
  where secexp = stretched_seedN seed
        mpk    = mpk_from_secret secexp
        z      = sequenceN n for_change mpk
        sk     = secexp + z

derive_pub :: Word32 -> Bool -> El_mpk -> PubKey
derive_pub n for_change mpk = PubKeyU pk
  where z   = sequenceN n for_change mpk
        zG  = mulPoint z curveG
        pk  = addPoint (point_mpk mpk) zG

hx_electrum_mpk :: BS -> BS
hx_electrum_mpk = encodeHex . mpk_bytes . derived_mpk . decode_seed

hx_electrum_stretch_seed :: BS -> BS
hx_electrum_stretch_seed
  = encodeHex . stretched_seed_bytes . decode_seed

hx_electrum_priv :: [BS] -> BS -> BS
hx_electrum_priv = hx_electrum_args "electrum-priv" decode_seed $ \n c s ->
                     B8.pack . toWIF $ derive_priv n c s

hx_electrum_sequence :: [BS] -> BS -> BS
hx_electrum_sequence = hx_electrum_args "electrum-sequence" decode_mpk $ \n c s ->
                         encodeHex $ sequenceBS n c s

hx_electrum_pub :: [BS] -> BS -> BS
hx_electrum_pub = hx_electrum_args "electrum-pub" decode_mpk $ \n c s ->
                    putHex $ derive_pub n c s

hx_electrum_addr :: [BS] -> BS -> BS
hx_electrum_addr = hx_electrum_args "electrum-addr" decode_mpk $ \n c s ->
                     B8.pack . addrToBase58 . pubKeyAddr $ derive_pub n c s

hx_electrum_args :: String -> (BS -> i) -> (Word32 -> Bool -> i -> BS) -> [BS] -> BS -> BS
hx_electrum_args name decode_input f args0 s =
  case args0 of
    []          -> usage
    n_str:args1 ->
      let n = parseWord32 "electrum sequence index" n_str in
      case args1 of
        [] -> f n False input
        for_change_str:args2 ->
          let for_change = read01 for_change_str in
          case args2 of
            [] -> f n for_change input
            [stop_str] ->
              let stop = parseWord32 "electrum sequence stop index" stop_str in
              B8.intercalate "\n" [f i for_change input | i <- [n..stop] ]
            _ -> usage
  where usage = error $ "Usage: hx " ++ name ++ " <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]"
        input = decode_input s
