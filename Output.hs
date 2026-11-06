{-# LANGUAGE OverloadedStrings #-}

-- | Structured output: YAML (the default) or JSON, with ANSI colors when the
-- output is a terminal.
--
-- Results are built as 'Val' trees whose object fields keep the order in
-- which they are given, so related fields stay together. A result that is a
-- single string is printed bare in YAML mode, which keeps shell pipelines
-- such as @hx bip39-seed | hx hd-priv@ working.
module Output
  ( -- * Values
    Val (..),
    ToVal (..),
    (.:),
    obj,
    hexV,

    -- * Output settings
    Style (..),
    ColorWhen (..),
    setStyle,
    getStyle,
    detectStyle,

    -- * Printing
    Out (..),
    Verdict (..),
    emitVal,
    renderVal,
    errorPrefix,
    colorHelp,
  )
where

import Control.Exception (evaluate)
import Control.Monad (unless)
import qualified Data.Aeson as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Char (isAlphaNum, isAscii, isDigit)
import Data.IORef
import Data.Int (Int32)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Encoding.Error as TE
import Data.Word (Word32, Word64, Word8)
import System.Environment (lookupEnv)
import System.Exit (ExitCode (..), exitWith)
import System.IO (hIsTerminalDevice, stderr, stdout)
import System.IO.Unsafe (unsafePerformIO)

-- * Values

data Val
  = Str !Text
  | Int !Integer
  | Bool !Bool
  | Null
  | List ![Val]
  | Obj ![(Text, Val)]
  deriving (Eq, Show)

class ToVal a where
  toVal :: a -> Val

instance ToVal Val where toVal = id

instance ToVal Text where toVal = Str

instance ToVal Bool where toVal = Bool

instance ToVal Integer where toVal = Int

instance ToVal Int where toVal = Int . toInteger

instance ToVal Int32 where toVal = Int . toInteger

instance ToVal Word8 where toVal = Int . toInteger

instance ToVal Word32 where toVal = Int . toInteger

instance ToVal Word64 where toVal = Int . toInteger

instance ToVal BS.ByteString where
  toVal = Str . TE.decodeUtf8With TE.lenientDecode

instance (ToVal a) => ToVal (Maybe a) where
  toVal = maybe Null toVal

instance (ToVal a) => ToVal [a] where
  toVal = List . map toVal

(.:) :: (ToVal v) => Text -> v -> (Text, Val)
k .: v = (k, toVal v)

infixr 8 .:

obj :: [(Text, Val)] -> Val
obj = Obj

-- | A hexadecimal string value.
hexV :: BS.ByteString -> Val
hexV = toVal

-- * Settings

data ColorWhen = ColorAuto | ColorAlways | ColorNever
  deriving (Eq, Show)

data Style = Style
  { styleJson :: !Bool,
    -- | colors on standard output
    styleColor :: !Bool,
    -- | colors on standard error
    styleColorErr :: !Bool,
    -- | indent JSON over several lines
    stylePretty :: !Bool
  }

{-# NOINLINE styleRef #-}
styleRef :: IORef Style
styleRef = unsafePerformIO (newIORef (Style False False False False))

-- | Set the output style. The style is evaluated first, so that an error in
-- the options it depends on is raised here and not when an error message is
-- being printed with it.
setStyle :: Style -> IO ()
setStyle st = evaluate st >>= writeIORef styleRef

getStyle :: IO Style
getStyle = readIORef styleRef

-- | Work out the output style from the options and the environment.
-- Colors follow https://no-color.org and TERM=dumb in auto mode.
detectStyle :: Bool -> ColorWhen -> IO Style
detectStyle json when = do
  outTty <- hIsTerminalDevice stdout
  noColor <- maybe False (not . null) <$> lookupEnv "NO_COLOR"
  term <- lookupEnv "TERM"
  let dumb = term == Just "dumb"
      allowed tty = case when of
        ColorAlways -> True
        ColorNever -> False
        ColorAuto -> tty && not noColor && not dumb
  errTty <- hIsTerminalDevice stderr
  return
    Style
      { styleJson = json,
        styleColor = allowed outTty,
        styleColorErr = allowed errTty,
        stylePretty = outTty
      }

-- * Colors

data Role = RKey | RStr | RNum | RTrue | RFalse | RNull | RPunct

paint :: Bool -> Role -> Text -> Text
paint False _ t = t
paint True r t = "\ESC[" <> code r <> "m" <> t <> "\ESC[0m"
  where
    code RKey = "1;34"
    code RStr = "32"
    code RNum = "36"
    code RTrue = "1;32"
    code RFalse = "1;31"
    code RNull = "90"
    code RPunct = "90"

errorPrefix :: IO Text
errorPrefix = do
  s <- getStyle
  return (paint (styleColorErr s) RFalse "hx:")

-- | Highlight the section titles of the help text.
colorHelp :: String -> IO String
colorHelp txt = do
  s <- getStyle
  let line l@('#' : _) = T.unpack (paint (styleColor s) RKey (T.pack l))
      line l = l
  return (unlines (map line (lines txt)))

-- * Rendering

renderVal :: Style -> Val -> Text
renderVal s v
  | styleJson s = renderJson (styleColor s) (stylePretty s) v <> "\n"
  | otherwise = renderYaml (styleColor s) v <> "\n"

-- JSON

jsonString :: Text -> Text
jsonString = TE.decodeUtf8 . LBS.toStrict . A.encode . A.String

jsonScalar :: Bool -> Val -> Text
jsonScalar c v = case v of
  Str t -> paint c RStr (jsonString t)
  Int i -> paint c RNum (T.pack (show i))
  Bool True -> paint c RTrue "true"
  Bool False -> paint c RFalse "false"
  Null -> paint c RNull "null"
  List [] -> "[]"
  Obj [] -> "{}"
  _ -> error "jsonScalar: not a scalar"

renderJson :: Bool -> Bool -> Val -> Text
renderJson c pretty = go 0
  where
    go ind v = case v of
      List xs@(_ : _) -> collection ind "[" "]" (map (go (ind + 2)) xs)
      Obj kvs@(_ : _) ->
        collection ind "{" "}" [paint c RKey (jsonString k) <> colon <> go (ind + 2) x | (k, x) <- kvs]
      _ -> jsonScalar c v
    colon = if pretty then ": " else ":"
    collection ind open close items
      | pretty =
          open
            <> "\n"
            <> T.intercalate ",\n" [T.replicate (ind + 2) " " <> i | i <- items]
            <> "\n"
            <> T.replicate ind " "
            <> close
      | otherwise = open <> T.intercalate "," items <> close

-- YAML

-- | Whether a string can be written as a plain YAML scalar, read back as the
-- same string by YAML 1.1 and 1.2 parsers.
plainOK :: Text -> Bool
plainOK t =
  case T.uncons t of
    Nothing -> False
    Just (h, _) ->
      isAlphaNum h
        && isAscii h
        && T.all safe t
        && not (looksNumeric t)
        && T.toLower t `notElem` reserved
        && not (": " `T.isInfixOf` t)
        && not (" #" `T.isInfixOf` t)
        && T.last t `notElem` (" :" :: String)
  where
    safe c = (isAlphaNum c && isAscii c) || c `elem` (" _.-/+=[]':" :: String)
    reserved = ["true", "false", "yes", "no", "on", "off", "y", "n", "null", "~"]
    looksNumeric s =
      T.all (\c -> isDigit c || c `elem` ("._:+-eE" :: String)) s
        || any (`T.isPrefixOf` T.toLower s) ["0x", "0o", "0b"]

yamlScalar :: Bool -> Val -> Text
yamlScalar c v = case v of
  Str t
    | plainOK t -> paint c RStr t
    | otherwise -> paint c RStr (jsonString t)
  _ -> jsonScalar c v

isCollection :: Val -> Bool
isCollection (List (_ : _)) = True
isCollection (Obj (_ : _)) = True
isCollection _ = False

renderYaml :: Bool -> Val -> Text
renderYaml c v = case v of
  -- a lone string prints bare, for shell pipelines
  Str t -> paint c RStr t
  _ | isCollection v -> T.intercalate "\n" (block 0 v)
  _ -> yamlScalar c v
  where
    dash = paint c RPunct "-"
    block :: Int -> Val -> [Text]
    block ind (Obj kvs) = concatMap (pair ind) kvs
    block ind (List xs) = concatMap (item ind) xs
    block _ x = [yamlScalar c x]
    pair ind (k, x)
      | isCollection x = (pad ind <> key k <> ":") : block (ind + 2) x
      | otherwise = [pad ind <> key k <> ": " <> yamlScalar c x]
    item ind x
      | isCollection x = case block (ind + 2) x of
          (first : rest) -> (pad ind <> dash <> " " <> T.drop (ind + 2) first) : rest
          [] -> []
      | otherwise = [pad ind <> dash <> " " <> yamlScalar c x]
    key k = paint c RKey (if plainOK k then k else jsonString k)
    pad n = T.replicate n " "

-- * Printing

emitVal :: Val -> IO ()
emitVal v = do
  s <- getStyle
  out <- evaluate (TE.encodeUtf8 (renderVal s v))
  BS.putStr out

-- | Things a command can print.
class Out a where
  emit :: a -> IO ()

instance Out Val where emit = emitVal

-- | A single string result.
instance Out BS.ByteString where emit = emitVal . toVal

-- | The answer of a verification: printed as true or false, and the exit
-- status is 1 when it is false.
newtype Verdict = Verdict Bool

instance Out Verdict where
  emit (Verdict b) = do
    emitVal (Bool b)
    unless b $ exitWith (ExitFailure 1)
