{-# LANGUAGE OverloadedStrings #-}

-- | Legacy (pre-2.0) Electrum deterministic wallets.
module Electrum
  ( hx_electrum_mpk,
    hx_electrum_stretch_seed,
    hx_electrum_priv,
    hx_electrum_pub,
    hx_electrum_addr,
    hx_electrum_sequence,
  )
where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Data.Word (Word32)
import EC
import Haskoin (Network)
import Keys (addrText, p2pkhOfPubBytes, secretToWif)
import Utils

data El_seed = El_seed {_seed_bytes :: BS, stretched_seed_bytes :: BS}

newtype El_mpk = El_mpk {mpk_bytes :: BS}

stretched_seedN :: El_seed -> Integer
stretched_seedN = (`mod` curveN) . bytesToInteger . stretched_seed_bytes

-- | Electrum sequence number used to derive keys. The mpk is raw bytes.
sequenceBS :: Word32 -> Bool -> El_mpk -> BS
sequenceBS n for_change mpk =
  hash256BS $ showB8 n <> ":" <> show01 for_change <> ":" <> mpk_bytes mpk

sequenceN :: Word32 -> Bool -> El_mpk -> Integer
sequenceN n c mpk
  | i < curveN = i
  | otherwise = error "electrum sequence number out of range"
  where
    i = bytesToInteger (sequenceBS n c mpk)

point_mpk :: El_mpk -> Point
point_mpk = either error id . decodePoint . BS.cons 0x04 . mpk_bytes

mpk_from_secret :: Integer -> El_mpk
mpk_from_secret = El_mpk . BS.drop 1 . encodePoint False . (`mulPoint` curveG)

derived_mpk :: El_seed -> El_mpk
derived_mpk = mpk_from_secret . stretched_seedN

stretch_seed :: BS -> El_seed
stretch_seed seed =
  El_seed seed $ iterate (sha256BS . (<> seedH)) seedH !! 100000
  where
    seedH = encodeHex seed

decode_seed :: BS -> El_seed
decode_seed = stretch_seed . decodeHexBytes "electrum seed" 16

decode_mpk :: BS -> El_mpk
decode_mpk s0
  | BS.length s == 32 = derived_mpk . decode_seed $ s
  | otherwise = El_mpk . decodeHexBytes "electrum master public key" 64 $ s
  where
    s = ignoreSpaces s0

derive_priv :: Word32 -> Bool -> El_seed -> Integer
derive_priv n for_change seed = (secexp + z) `mod` curveN
  where
    secexp = stretched_seedN seed
    z = sequenceN n for_change (mpk_from_secret secexp)

derive_pub :: Word32 -> Bool -> El_mpk -> Point
derive_pub n for_change mpk =
  addPoint (point_mpk mpk) (mulPoint (sequenceN n for_change mpk) curveG)

hx_electrum_mpk :: BS -> BS
hx_electrum_mpk = encodeHex . mpk_bytes . derived_mpk . decode_seed

hx_electrum_stretch_seed :: BS -> BS
hx_electrum_stretch_seed = encodeHex . stretched_seed_bytes . decode_seed

hx_electrum_priv :: Network -> [BS] -> BS -> BS
hx_electrum_priv net = hx_electrum_args "electrum-priv" decode_seed $ \n c s ->
  secretToWif net False (derive_priv n c s)

hx_electrum_sequence :: [BS] -> BS -> BS
hx_electrum_sequence = hx_electrum_args "electrum-seq" decode_mpk $ \n c s ->
  encodeHex $ sequenceBS n c s

hx_electrum_pub :: [BS] -> BS -> BS
hx_electrum_pub = hx_electrum_args "electrum-pub" decode_mpk $ \n c s ->
  encodeHex . encodePoint False $ derive_pub n c s

hx_electrum_addr :: Network -> [BS] -> BS -> BS
hx_electrum_addr net = hx_electrum_args "electrum-addr" decode_mpk $ \n c s ->
  addrText net . p2pkhOfPubBytes . encodePoint False $ derive_pub n c s

hx_electrum_args :: String -> (BS -> i) -> (Word32 -> Bool -> i -> BS) -> [BS] -> BS -> BS
hx_electrum_args name decode_input f args0 s =
  case args0 of
    [] -> usage
    n_str : args1 ->
      let n = parseWord32 "electrum sequence index" n_str
       in case args1 of
            [] -> f n False input
            for_change_str : args2 ->
              let for_change = read01 for_change_str
               in case args2 of
                    [] -> f n for_change input
                    [stop_str] ->
                      let stop = parseWord32 "electrum sequence stop index" stop_str
                       in B8.intercalate "\n" [f i for_change input | i <- [n .. stop]]
                    _ -> usage
  where
    usage = error $ "Usage: hx " ++ name ++ " <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]"
    input = decode_input s
