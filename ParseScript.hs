module ParseScript
  (parseOp
  ,parseScript
  ,parseReadP) where

import Network.Haskoin.Internals (Script(..),ScriptOp(..),opPushData)
import Data.Char (isHexDigit,isDigit,toUpper,isAlphaNum)
import Data.ByteString.Char8 (ByteString,pack)
import Data.Word (Word8)
import qualified Data.ByteString.Base16 as B16
import Text.ParserCombinators.ReadP hiding (many)
import Control.Applicative

type Parser a = ReadP a

wordBoundary :: Parser ()
wordBoundary = do
  cs <- look
  case cs of
    (c:_) | isAlphaNum c -> pfail
    _                    -> return ()

tokP :: Parser a -> Parser ()
tokP p = p *> wordBoundary *> skipSpaces

tok :: String -> Parser ()
tok = tokP . string

bracket :: Parser a -> Parser a
bracket p = tok "[" *> p <* tok "]"

int :: Int -> Parser ()
int = tok . show

hexDigit :: Parser Char
hexDigit = satisfy isHexDigit

hex :: Parser ByteString
hex = fst . B16.decode . pack <$> some hexDigit <* skipSpaces

word8 :: Parser Word8
word8 = read <$> some (satisfy isDigit) <* skipSpaces

op :: String -> Parser ()
op s = tokP (foldr1 (<|>) . map string $ [s, up s, "op_" ++ s, "OP_" ++ up s])
  where up = map toUpper

parseOp :: Parser ScriptOp
parseOp
  =  opPushData <$> bracket hex
 -- Constants
 <|> OP_0                  <$ int 0
 <|> OP_1NEGATE            <$ int (-1)
 <|> OP_RESERVED           <$ op "reserved"
 <|> OP_1                  <$ int 1
 <|> OP_2                  <$ int 2
 <|> OP_3                  <$ int 3
 <|> OP_4                  <$ int 4
 <|> OP_5                  <$ int 5
 <|> OP_6                  <$ int 6
 <|> OP_7                  <$ int 7
 <|> OP_8                  <$ int 8
 <|> OP_9                  <$ int 9
 <|> OP_10                 <$ int 10
 <|> OP_11                 <$ int 11
 <|> OP_12                 <$ int 12
 <|> OP_13                 <$ int 13
 <|> OP_14                 <$ int 14
 <|> OP_15                 <$ int 15
 <|> OP_16                 <$ int 16

 -- Crypto Constants
 <|> OP_PUBKEY             <$ op "pubkey"
 <|> OP_PUBKEYHASH         <$ op "pubkeyhash"

 -- Invalid Opcodes
 <|> OP_INVALIDOPCODE      <$ op "invalidopcode" <*> word8

 -- Flow Control
 <|> OP_NOP                <$ op "nop"
 <|> OP_VER                <$ op "ver"
 <|> OP_IF                 <$ op "if"
 <|> OP_NOTIF              <$ op "notif"
 <|> OP_VERIF              <$ op "verif"
 <|> OP_VERNOTIF           <$ op "vernotif"
 <|> OP_ELSE               <$ op "else"
 <|> OP_ENDIF              <$ op "endif"
 <|> OP_VERIFY             <$ op "verify"
 <|> OP_RETURN             <$ op "return"

 -- Stack Operations
 <|> OP_TOALTSTACK         <$ op "toaltstack"
 <|> OP_FROMALTSTACK       <$ op "fromaltstack"
 <|> OP_2DROP              <$ op "2drop"
 <|> OP_2DUP               <$ op "2dup"
 <|> OP_3DUP               <$ op "3dup"
 <|> OP_2OVER              <$ op "2over"
 <|> OP_2ROT               <$ op "2rot"
 <|> OP_2SWAP              <$ op "2swap"
 <|> OP_IFDUP              <$ op "ifdup"
 <|> OP_DEPTH              <$ op "depth"
 <|> OP_DROP               <$ op "drop"
 <|> OP_DUP                <$ op "dup"
 <|> OP_NIP                <$ op "nip"
 <|> OP_OVER               <$ op "over"
 <|> OP_PICK               <$ op "pick"
 <|> OP_ROLL               <$ op "roll"
 <|> OP_ROT                <$ op "rot"
 <|> OP_SWAP               <$ op "swap"
 <|> OP_TUCK               <$ op "tuck"

 -- Splice
 <|> OP_CAT                <$ op "cat"
 <|> OP_SUBSTR             <$ op "substr"
 <|> OP_LEFT               <$ op "left"
 <|> OP_RIGHT              <$ op "right"
 <|> OP_SIZE               <$ op "size"

 -- Bitwise Logic
 <|> OP_INVERT             <$ op "invert"
 <|> OP_AND                <$ op "and"
 <|> OP_OR                 <$ op "or"
 <|> OP_XOR                <$ op "xor"
 <|> OP_EQUAL              <$ op "equal"
 <|> OP_EQUALVERIFY        <$ op "equalverify"
 <|> OP_RESERVED1          <$ op "reserved1"
 <|> OP_RESERVED2          <$ op "reserved2"

 -- Arithmetic
 <|> OP_1ADD               <$ op "1add"
 <|> OP_1SUB               <$ op "1sub"
 <|> OP_2MUL               <$ op "2mul"
 <|> OP_2DIV               <$ op "2div"
 <|> OP_NEGATE             <$ op "negate"
 <|> OP_ABS                <$ op "abs"
 <|> OP_NOT                <$ op "not"
 <|> OP_0NOTEQUAL          <$ op "0notequal"
 <|> OP_ADD                <$ op "add"
 <|> OP_SUB                <$ op "sub"
 <|> OP_MUL                <$ op "mul"
 <|> OP_DIV                <$ op "div"
 <|> OP_MOD                <$ op "mod"
 <|> OP_LSHIFT             <$ op "lshift"
 <|> OP_RSHIFT             <$ op "rshift"
 <|> OP_BOOLAND            <$ op "booland"
 <|> OP_BOOLOR             <$ op "boolor"
 <|> OP_NUMEQUAL           <$ op "numequal"
 <|> OP_NUMEQUALVERIFY     <$ op "numequalverify"
 <|> OP_NUMNOTEQUAL        <$ op "numnotequal"
 <|> OP_LESSTHAN           <$ op "lessthan"
 <|> OP_GREATERTHAN        <$ op "greaterthan"
 <|> OP_LESSTHANOREQUAL    <$ op "lessthanorequal"
 <|> OP_GREATERTHANOREQUAL <$ op "greaterthanorequal"
 <|> OP_MIN                <$ op "min"
 <|> OP_MAX                <$ op "max"
 <|> OP_WITHIN             <$ op "within"

 -- Crypto
 <|> OP_RIPEMD160          <$ op "ripemd160"
 <|> OP_SHA1               <$ op "sha1"
 <|> OP_SHA256             <$ op "sha256"
 <|> OP_HASH160            <$ op "hash160"
 <|> OP_HASH256            <$ op "hash256"
 <|> OP_CODESEPARATOR      <$ op "codeseparator"
 <|> OP_CHECKSIG           <$ op "checksig"
 <|> OP_CHECKSIGVERIFY     <$ op "checksigverify"
 <|> OP_CHECKMULTISIG      <$ op "checkmultisig"
 <|> OP_CHECKMULTISIGVERIFY<$ op "checkmultisigverify"

 -- More NOPs
 <|> OP_NOP1               <$ op "nop1"
 <|> OP_NOP2               <$ op "nop2"
 <|> OP_NOP3               <$ op "nop3"
 <|> OP_NOP4               <$ op "nop4"
 <|> OP_NOP5               <$ op "nop5"
 <|> OP_NOP6               <$ op "nop6"
 <|> OP_NOP7               <$ op "nop7"
 <|> OP_NOP8               <$ op "nop8"
 <|> OP_NOP9               <$ op "nop9"
 <|> OP_NOP10              <$ op "nop10"

parseScript :: Parser Script
parseScript = Script <$> many parseOp

parseReadP :: Show a => Parser a -> String -> a
parseReadP p s =
  case readP_to_S (skipSpaces *> p <* eof) s of
    (x,""):_ -> x
    [_]      -> error "trailing characters"
    []       -> error "no parses"
    _        -> error "too many parses"
