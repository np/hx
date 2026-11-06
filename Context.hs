-- | The libsecp256k1 context shared by the whole program.
--
-- Nearly every Haskoin function needs a 'Ctx'. Creating one is costly and it
-- is never mutated afterwards, so a single process-wide context lets the rest
-- of the code stay pure.
module Context (ctx) where

import Crypto.Secp256k1 (Ctx, createContext)
import System.IO.Unsafe (unsafePerformIO)

{-# NOINLINE ctx #-}
ctx :: Ctx
ctx = unsafePerformIO createContext
