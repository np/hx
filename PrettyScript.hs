module PrettyScript
  (prettyOp
  ,prettyOps
  ,prettyScript
  ,showDoc
  ) where

import Network.Haskoin.Internals (Script(..),ScriptOp(..))
import Data.ByteString.Char8 (ByteString,unpack)
import Data.List (intersperse)
import qualified Data.ByteString.Base16 as B16

type Doc = ShowS

tok :: String -> Doc
tok = (++)

(<+>) :: Doc -> Doc -> Doc
x <+> y = x . tok " " . y

sep :: [Doc] -> Doc
sep = foldr (.) id . intersperse (tok " ")

bracket :: Doc -> Doc
bracket d = tok "[ " . d . tok " ]"

int :: Int -> Doc
int = tok . show

hex :: ByteString -> Doc
hex = tok . unpack . B16.encode

prettyOp :: ScriptOp -> Doc
prettyOp o = case o of
    OP_PUSHDATA ws _d     -> bracket $ hex ws

    -- Constants
    OP_0                  -> int 0
    OP_1NEGATE            -> int (-1)
    OP_RESERVED           -> tok "reserved"
    OP_1                  -> int 1
    OP_2                  -> int 2
    OP_3                  -> int 3
    OP_4                  -> int 4
    OP_5                  -> int 5
    OP_6                  -> int 6
    OP_7                  -> int 7
    OP_8                  -> int 8
    OP_9                  -> int 9
    OP_10                 -> int 10
    OP_11                 -> int 11
    OP_12                 -> int 12
    OP_13                 -> int 13
    OP_14                 -> int 14
    OP_15                 -> int 15
    OP_16                 -> int 16

    -- Crypto Constants
    OP_PUBKEY             -> tok "pubkey"
    OP_PUBKEYHASH         -> tok "pubkeyhash"

    -- Invalid Opcodes
    OP_INVALIDOPCODE x    -> tok "invalidopcode" <+> tok (show x)

    -- Flow Control
    OP_NOP                -> tok "nop"
    OP_VER                -> tok "ver"
    OP_IF                 -> tok "if"
    OP_NOTIF              -> tok "notif"
    OP_VERIF              -> tok "verif"
    OP_VERNOTIF           -> tok "vernotif"
    OP_ELSE               -> tok "else"
    OP_ENDIF              -> tok "endif"
    OP_VERIFY             -> tok "verify"
    OP_RETURN             -> tok "return"

    -- Stack Operations
    OP_TOALTSTACK         -> tok "toaltstack"
    OP_FROMALTSTACK       -> tok "fromaltstack"
    OP_2DROP              -> tok "2drop"
    OP_2DUP               -> tok "2dup"
    OP_3DUP               -> tok "3dup"
    OP_2OVER              -> tok "2over"
    OP_2ROT               -> tok "2rot"
    OP_2SWAP              -> tok "2swap"
    OP_IFDUP              -> tok "ifdup"
    OP_DEPTH              -> tok "depth"
    OP_DROP               -> tok "drop"
    OP_DUP                -> tok "dup"
    OP_NIP                -> tok "nip"
    OP_OVER               -> tok "over"
    OP_PICK               -> tok "pick"
    OP_ROLL               -> tok "roll"
    OP_ROT                -> tok "rot"
    OP_SWAP               -> tok "swap"
    OP_TUCK               -> tok "tuck"

    -- Splice
    OP_CAT                -> tok "cat"
    OP_SUBSTR             -> tok "substr"
    OP_LEFT               -> tok "left"
    OP_RIGHT              -> tok "right"
    OP_SIZE               -> tok "size"

    -- Bitwise Logic
    OP_INVERT             -> tok "invert"
    OP_AND                -> tok "and"
    OP_OR                 -> tok "or"
    OP_XOR                -> tok "xor"
    OP_EQUAL              -> tok "equal"
    OP_EQUALVERIFY        -> tok "equalverify"
    OP_RESERVED1          -> tok "reserved1"
    OP_RESERVED2          -> tok "reserved2"

    -- Arithmetic
    OP_1ADD               -> tok "1add"
    OP_1SUB               -> tok "1sub"
    OP_2MUL               -> tok "2mul"
    OP_2DIV               -> tok "2div"
    OP_NEGATE             -> tok "negate"
    OP_ABS                -> tok "abs"
    OP_NOT                -> tok "not"
    OP_0NOTEQUAL          -> tok "0notequal"
    OP_ADD                -> tok "add"
    OP_SUB                -> tok "sub"
    OP_MUL                -> tok "mul"
    OP_DIV                -> tok "div"
    OP_MOD                -> tok "mod"
    OP_LSHIFT             -> tok "lshift"
    OP_RSHIFT             -> tok "rshift"
    OP_BOOLAND            -> tok "booland"
    OP_BOOLOR             -> tok "boolor"
    OP_NUMEQUAL           -> tok "numequal"
    OP_NUMEQUALVERIFY     -> tok "numequalverify"
    OP_NUMNOTEQUAL        -> tok "numnotequal"
    OP_LESSTHAN           -> tok "lessthan"
    OP_GREATERTHAN        -> tok "greaterthan"
    OP_LESSTHANOREQUAL    -> tok "lessthanorequal"
    OP_GREATERTHANOREQUAL -> tok "greaterthanorequal"
    OP_MIN                -> tok "min"
    OP_MAX                -> tok "max"
    OP_WITHIN             -> tok "within"

    -- Crypto
    OP_RIPEMD160          -> tok "ripemd160"
    OP_SHA1               -> tok "sha1"
    OP_SHA256             -> tok "sha256"
    OP_HASH160            -> tok "hash160"
    OP_HASH256            -> tok "hash256"
    OP_CODESEPARATOR      -> tok "codeseparator"
    OP_CHECKSIG           -> tok "checksig"
    OP_CHECKSIGVERIFY     -> tok "checksigverify"
    OP_CHECKMULTISIG      -> tok "checkmultisig"
    OP_CHECKMULTISIGVERIFY-> tok "checkmultisigverify"

    -- More NOPs
    OP_NOP1               -> tok "nop1"
    OP_NOP2               -> tok "nop2"
    OP_NOP3               -> tok "nop3"
    OP_NOP4               -> tok "nop4"
    OP_NOP5               -> tok "nop5"
    OP_NOP6               -> tok "nop6"
    OP_NOP7               -> tok "nop7"
    OP_NOP8               -> tok "nop8"
    OP_NOP9               -> tok "nop9"
    OP_NOP10              -> tok "nop10"

prettyOps :: [ScriptOp] -> Doc
prettyOps = sep . map prettyOp

prettyScript :: Script -> Doc
prettyScript = prettyOps . scriptOps

showDoc :: Doc -> String
showDoc d = d ""
