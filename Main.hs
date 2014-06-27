{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where 

import Control.Arrow (first) 
import Control.Monad
import Control.Applicative
import Debug.Trace

import Data.Bits
import Data.Either.Unwrap
import Data.Foldable (for_)
import Data.Maybe ( fromJust, fromMaybe, isJust )
import Data.List.Split (splitOn)
import Data.List (union, (\\))
-- import Data.Binary (encodeFile, decodeFile)
import Data.Binary 
import GHC.Generics (Generic)
import qualified Data.Text as T
import Data.Text.Read
import Data.Time.Clock
import Data.Time.Clock.POSIX

import Database.MySQL.Simple hiding (Binary)
import Database.MySQL.Simple.QueryResults
import Database.MySQL.Simple.Result
import Database.MySQL.Simple.Param

import System.Environment
import System.Console.GetOpt
import System.Exit (exitWith, ExitCode(ExitSuccess))
import System.FilePath.Posix ((</>))

import Shelly hiding (FilePath, (</>))

data Event         = Event 
 { srcIP          :: T.Text
 , descr          :: T.Text
 } deriving (Generic, Show)

instance QueryResults Event where
    convertResults [fa,fb] [va,vb] = Event (decimalToIP a) b
        where a = convert fa va
              b = convert fb vb
    convertResults fs vs  = convertError fs vs 2

data Options       = Options
 { optVerbose     :: Bool
 , optShowVersion :: Bool
 , optFlushSig    :: Bool
 , optListSig     :: Bool
 , optSignature   :: [Int]
 , optDelSig      :: [Int]
 , optWorkDir     :: FilePath
 } deriving Show

defaultOptions    = Options
 { optVerbose     = False
 , optShowVersion = False
 , optFlushSig    = False
 , optListSig     = False
 , optSignature   = []
 , optDelSig      = []
 , optWorkDir     = "." 
 }

connInfo               = defaultConnectInfo
  { connectHost        = "localhost"
  , connectUser        = "root"
  -- , connectPassword    = "gits"
  , connectDatabase    = "securityonion_db"
  }

options :: [OptDescr (Options -> Options)]
options =
 [ Option ['v'] ["verbose"]
     (NoArg (\ opts -> opts { optVerbose = True }))
     "enable verbose messages"
 , Option ['V','?'] ["version"]
     (NoArg (\ opts -> opts { optShowVersion = True }))
     "show version number"
 , Option ['l'] ["list"]
     (NoArg (\ opts -> opts { optListSig = True }))
     "list signatures"
 , Option ['f'] ["flush"]
     (NoArg (\ opts -> opts { optFlushSig = True }))
     "flush signatures"
 , Option ['s'] ["signature"]
     (OptArg (\s opts -> opts { optSignature = sigToList s} )
     "Sig,Sig,Sig,...,Sig") "add signatures"
 , Option ['d'] ["delete"]
     (OptArg (\s opts -> opts { optDelSig = sigToList s} )
     "Sig,Sig,Sig,...,Sig") "delete signatures"
 , Option ['w'] ["work-directory"]
     (OptArg (\s opts -> opts { optWorkDir = (fromJust s) } )
     "Directory") "Working Directory"
 ]

sigToList :: Maybe String -> [Int]
sigToList ms 
  | isJust ms = ( ( (map (read) ) . (splitOn "," ) ) (fromJust ms) ) :: [Int] 
  | otherwise = []

pfctl :: T.Text
pfctl = "pfctl -t SNORT -T add"

firewallsIP :: [T.Text]
firewallsIP = ["172.16.9.1","172.16.9.2"]

firewallUsers :: T.Text 
firewallUsers = "root@"

datFile :: FilePath -> FilePath
datFile d = (</>) d "sigList.dat"

timeDat :: FilePath -> FilePath
timeDat d = d </> "timeStamp.dat"

readSigList :: FilePath -> IO [Int]
readSigList f = decodeFile f

writeSigList :: FilePath -> [Int] -> IO ()
writeSigList f t = encodeFile f t

writeTime :: FilePath -> IO ()
writeTime f = getCurrentTime >>= encodeFile f . toTimeStamp 

readTime :: FilePath -> IO UTCTime
readTime f =  (decodeFile f) >>= return . fromTimeStamp

toTimeStamp :: UTCTime -> Integer
toTimeStamp utc = fromIntegral . floor . utcTimeToPOSIXSeconds $ utc

fromTimeStamp :: Integer -> UTCTime
fromTimeStamp i = posixSecondsToUTCTime . realToFrac . fromIntegral $ i 

decimalToIP :: Int -> T.Text
decimalToIP n = foldl (\ s i -> s `T.append` (wordToIPString i (decimalToQuarter n (i * 8)))) "" [3,2,1,0]
  where 
    decimalToQuarter a b = ((.&.) 0xff . shiftR a) b

wordToIPString :: Int -> Int -> T.Text
wordToIPString i n
  | i >  2 = T.pack $ show n
  | i <= 2 = T.pack $ (showString "." . shows n) []

ipToDecimal :: T.Text -> Int
ipToDecimal str = foldl (\r (x,y)  -> (.|.) r (shiftL x (y*8)) ) 0 (ipToList str)
  where 
    ipToList str = zip ( (map (fst . fromRight . decimal ) . (T.splitOn  "." ) ) str ) [3,2,1,0] 

main :: IO ()
main = getArgs >>= compilerOpts >>= compile >>= print

compilerOpts :: [String] -> IO (Options, [FilePath])
compilerOpts argv =
   case getOpt Permute options argv of
      (o,n,[] ) -> return (foldl (flip id) defaultOptions o, n)
      (_,_,errs) -> ioError (userError (concat errs ++ usageInfo header options))

header :: String
header = "Usage: main [OPTION...] files..."

compile :: (Options, [FilePath]) -> IO [Int] 
compile (o, f)
  | (optListSig o)  = readSigList $ datFile $ optWorkDir o
  | (optFlushSig o) = do
                        writeSigList (datFile (optWorkDir o)) []
                        return $ []
  | ( not . null ) ( optDelSig o) = do 
                                     sigList <- readSigList $ datFile (optWorkDir o)
                                     let result = (\\) sigList $ optDelSig o
                                     writeSigList ( datFile (optWorkDir o)) result
                                     return $ result 
  | ( not . null ) ( optSignature o ) = do 
                                          sigList <- readSigList $ datFile (optWorkDir o)
                                          let result = sigList `union` (optSignature o)
                                          writeSigList (datFile (optWorkDir o) ) $ result
                                          return $ result
  | otherwise = do
                  sigList <- readSigList $ datFile (optWorkDir o)
                  t0 <- readTime $ timeDat (optWorkDir o)
                  e <- getBadIPs sigList t0 
                  shelly $ blockIPs e
                  writeTime $ timeDat (optWorkDir o)
                  return $ sigList

getBadIPs :: [Int] -> UTCTime -> IO [Event]
getBadIPs s t0 = do 
              conn <- connect connInfo 
              e <- query conn "SELECT src_ip, signature FROM event WHERE signature_id IN ? and timestamp > ?" (In s, t0) 
              close conn
              return e

blockIPs :: [Event] -> Sh ()
blockIPs el = let ipList = map (\ e -> (srcIP e) ) el 
                  firewalls = map (\ ip -> firewallUsers `T.append` ip ) firewallsIP
                  in for_ firewalls (commFirewall ipList)

commFirewall :: [T.Text] -> T.Text -> Sh ()
commFirewall args f = shelly $ run_ "ssh" $ f:pfctl:args

