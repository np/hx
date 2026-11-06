-- | Plain arithmetic on the secp256k1 curve.
--
-- libsecp256k1 deliberately hides field elements and cannot represent the
-- point at infinity, while the @ec-*@ commands expose exactly those. This
-- small, non constant-time implementation backs those commands and the
-- legacy Electrum key derivation. Never use it with secrets that matter.
module EC
  ( Point (..),
    curveP,
    curveN,
    curveA,
    curveB,
    curveG,
    addPoint,
    doublePoint,
    mulPoint,
    pointX,
    pointY,
    encodePoint,
    decodePoint,
    integerToBytes32,
    bytesToInteger,
  )
where

import Data.Bits (shiftL, shiftR, testBit, (.&.), (.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

data Point = Infinity | Point !Integer !Integer
  deriving (Eq, Show)

curveP, curveN, curveA, curveB :: Integer
curveP = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
curveN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
curveA = 0
curveB = 7

curveG :: Point
curveG =
  Point
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

powMod :: Integer -> Integer -> Integer -> Integer
powMod _ 0 m = 1 `mod` m
powMod b e m
  | even e = let h = powMod b (e `div` 2) m in h * h `mod` m
  | otherwise = b * powMod b (e - 1) m `mod` m

invP :: Integer -> Integer
invP x = powMod (x `mod` curveP) (curveP - 2) curveP

addPoint :: Point -> Point -> Point
addPoint Infinity q = q
addPoint p Infinity = p
addPoint p@(Point x1 y1) (Point x2 y2)
  | x1 == x2 && (y1 + y2) `mod` curveP == 0 = Infinity
  | x1 == x2 = doublePoint p
  | otherwise = Point x3 y3
  where
    l = (y2 - y1) * invP (x2 - x1) `mod` curveP
    x3 = (l * l - x1 - x2) `mod` curveP
    y3 = (l * (x1 - x3) - y1) `mod` curveP

doublePoint :: Point -> Point
doublePoint Infinity = Infinity
doublePoint (Point x y)
  | y == 0 = Infinity
  | otherwise = Point x3 y3
  where
    l = (3 * x * x + curveA) * invP (2 * y) `mod` curveP
    x3 = (l * l - 2 * x) `mod` curveP
    y3 = (l * (x - x3) - y) `mod` curveP

-- | Scalar multiplication (double-and-add).
mulPoint :: Integer -> Point -> Point
mulPoint k0 p0 = go (k0 `mod` curveN) p0 Infinity
  where
    go 0 _ acc = acc
    go k p acc =
      go (k `shiftR` 1) (doublePoint p) (if testBit k 0 then addPoint acc p else acc)

pointX, pointY :: Point -> Maybe Integer
pointX (Point x _) = Just x
pointX Infinity = Nothing
pointY (Point _ y) = Just y
pointY Infinity = Nothing

isOnCurve :: Point -> Bool
isOnCurve Infinity = True
isOnCurve (Point x y) =
  x >= 0 && x < curveP && y >= 0 && y < curveP
    && (y * y - (x * x * x + curveA * x + curveB)) `mod` curveP == 0

-- | SEC 1 encoding. The point at infinity is the single byte @00@.
encodePoint :: Bool -> Point -> ByteString
encodePoint _ Infinity = BS.singleton 0
encodePoint True (Point x y) =
  BS.cons (if even y then 2 else 3) (integerToBytes32 x)
encodePoint False (Point x y) =
  BS.cons 4 (integerToBytes32 x <> integerToBytes32 y)

decodePoint :: ByteString -> Either String Point
decodePoint bs = case BS.uncons bs of
  Just (0, rest) | BS.null rest -> Right Infinity
  Just (h, rest)
    | (h == 2 || h == 3) && BS.length rest == 32 -> do
        let x = bytesToInteger rest
            rhs = (x * x * x + curveA * x + curveB) `mod` curveP
            y0 = powMod rhs ((curveP + 1) `div` 4) curveP
            y = if odd y0 == (h == 3) then y0 else curveP - y0
            pt = Point x y
        check pt
    | h == 4 && BS.length rest == 64 ->
        let (xb, yb) = BS.splitAt 32 rest
         in check (Point (bytesToInteger xb) (bytesToInteger yb))
  _ -> Left "invalid curve point encoding"
  where
    check pt
      | isOnCurve pt = Right pt
      | otherwise = Left "point is not on the curve"

integerToBytes32 :: Integer -> ByteString
integerToBytes32 i = BS.pack [fromInteger ((i `shiftR` (8 * k)) .&. 0xff) | k <- [31, 30 .. 0]]

bytesToInteger :: ByteString -> Integer
bytesToInteger = BS.foldl' (\acc w -> (acc `shiftL` 8) .|. fromIntegral w) 0
