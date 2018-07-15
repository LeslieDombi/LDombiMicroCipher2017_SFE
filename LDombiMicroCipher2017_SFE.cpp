// LDombiMicroCipher2017_SFE.cpp : Defines the entry point for the console application.
//

#include <stdint.h>
#include <stdio.h>
#include <windows.h>

#include "ErrorCodes.h"

#include "LDombiMicroCipher2017.hpp"



#define MAX_BUF_LEN 0x1000000

#define DEFAULT_Depth ldmc_DEPTH_DEF
#define DEFAULT_Noise ldmc_NOISE_DEF
#define DEFAULT_Seed  ldmc_SEED_DEF

typedef enum eBlockMode
{

  BLOCK_FWD,
  BLOCK_BWD,
  BLOCK_BID,
  BLOCK_DIB

} tBlockMode, *pBlockMode;



ldmc_tByte KeyP[ldmc_KEY_LEN_MAX];
ldmc_tByte KeyS[ldmc_KEY_LEN_MAX];

    ldmc_tCipherContext     CipherContext;
ldmc_tDualCipherContext DualCipherContext;



int TranslateCipherError(ldmc_tErrorCode ErrorCode);
int VisualizeReturnValue(int ReturnValue);
BOOL GetNumber(char sNumber[], uint64_t *pNumber);
const char *ParseDstFileParameter(const char *SrcName, const char *DstName, BOOL *pSrcFileIsDstFile);
BOOL ParseModeParameter(char sPar[], BOOL *pDeCrypt, BOOL *pDualRun, pBlockMode pMode, uint64_t *pBlockSize, BOOL *pResetPerBlock);
const char *ParseKeyParameter(char sPar[], BOOL *pKeyFile);
BOOL ParseDepthParameter(char sPar[], uint64_t *pDepth);
BOOL ParseNoiseParameter(char sPar[], uint64_t *pNoise);
BOOL ParseSeedParameter(char sPar[], uint64_t *pSeed);
int LoadKey(BOOL KeyFile, const char KeyPar[], ldmc_tByte Key[], uint64_t *pKeyLen);



int main(int argc, char *argv[])
{
  int RetVal = ERROR_CODE_NO_ERROR;
  const char *SrcFileName = NULL, *DstFileName = NULL;
  BOOL SrcFileIsDstFile = FALSE;
  BOOL DualRun = FALSE, DeCrypt = FALSE;
  tBlockMode BlockMode = BLOCK_FWD;
  uint64_t BlockSize = MAX_BUF_LEN;
  BOOL ResetPerBlock = FALSE;
  DWORD DualIni = 0;
  const char *KeyParP = NULL, *KeyParS = NULL;
  BOOL KeyFileP = FALSE, KeyFileS = FALSE;
  uint64_t KeyLenP = 0, KeyLenS = 0;
  uint64_t DepthP = DEFAULT_Depth, NoiseP = DEFAULT_Noise, SeedP = DEFAULT_Seed, DepthS = DEFAULT_Depth, NoiseS = DEFAULT_Noise, SeedS = DEFAULT_Seed;
  ldmc_pDualBlockProcessor pDualBlockProcessor;
      ldmc_pBlockProcessor     pBlockProcessor;

  switch ( argc )
  {
    case 12:
      if ( !ParseSeedParameter(argv[11], &SeedS) )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      DualIni++;
    case 11:
      if ( !ParseNoiseParameter(argv[10], &NoiseS) )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      DualIni++;
    case 10:
      if ( !ParseDepthParameter(argv[9], &DepthS) )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      DualIni++;
    case  9:
      if ( (KeyParS = ParseKeyParameter(argv[8], &KeyFileS)) == NULL )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      DualIni++;
    case  8:
      if ( !ParseSeedParameter(argv[7], &SeedP) )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
    case  7:
      if ( !ParseNoiseParameter(argv[6], &NoiseP) )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
    case  6:
      if ( !ParseDepthParameter(argv[5], &DepthP) )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
    case  5:
      if ( (KeyParP = ParseKeyParameter(argv[4], &KeyFileP)) == NULL )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      if ( !ParseModeParameter(argv[3], &DeCrypt, &DualRun, &BlockMode, &BlockSize, &ResetPerBlock) )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      if ( (DstFileName = ParseDstFileParameter(SrcFileName = argv[1], argv[2], &SrcFileIsDstFile)) == NULL )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      break;

    default:
      RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      break;
  }

  if ( RetVal == ERROR_CODE_NO_ERROR )
  {
    switch ( BlockMode )
    {
      case BLOCK_FWD:
        pDualBlockProcessor = DeCrypt ? ldmc_DualDeCryptBlockFWD : ldmc_DualEnCryptBlockFWD;
            pBlockProcessor = DeCrypt ?     ldmc_DeCryptBlockFWD :     ldmc_EnCryptBlockFWD;
        break;
      case BLOCK_BWD:
        pDualBlockProcessor = DeCrypt ? ldmc_DualDeCryptBlockBWD : ldmc_DualEnCryptBlockBWD;
            pBlockProcessor = DeCrypt ?     ldmc_DeCryptBlockBWD :     ldmc_EnCryptBlockBWD;
        break;
      case BLOCK_BID:
        if ( !DualRun )
        {
          RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
          break;
        }
        pDualBlockProcessor = DeCrypt ? ldmc_DualDeCryptBlockBID : ldmc_DualEnCryptBlockBID;
        break;
      case BLOCK_DIB:
        if ( !DualRun )
        {
          RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
          break;
        }
        pDualBlockProcessor = DeCrypt ? ldmc_DualDeCryptBlockDIB : ldmc_DualEnCryptBlockDIB;
        break;
      default:
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
        break;
    }
  }

  if ( RetVal == ERROR_CODE_NO_ERROR )
  {
    RetVal = LoadKey(KeyFileP, KeyParP, KeyP, &KeyLenP);
  }

  if (( RetVal == ERROR_CODE_NO_ERROR ) && ( DualIni ))
  {
    RetVal = LoadKey(KeyFileS, KeyParS, KeyS, &KeyLenS);
  }

  if ( RetVal == ERROR_CODE_NO_ERROR )
  {
    if (( DualIni ) && ( !DualRun ))
      RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
    else
    {
      switch ( DualIni )
      {
        case 1:
          DepthS = DepthP;
        case 2:
          NoiseS = NoiseP;
        case 3:
           SeedS =  SeedP;
        case 4:
        case 0:
          break;
        default:
          RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
          break;
      }
    }
  }

  if ( RetVal == ERROR_CODE_NO_ERROR )
  {
    ldmc_tErrorCode ChiperErrorCode;
    if ( DualRun )
      if ( DualIni )
        ChiperErrorCode = ldmc_DualDetailedInitCipherContexts(&DualCipherContext, KeyP, (unsigned int)KeyLenP, (unsigned int)DepthP, (unsigned int)NoiseP, (ldmc_tSeed)SeedP, KeyS, (unsigned int)KeyLenS, (unsigned int)DepthS, (unsigned int)NoiseS, (ldmc_tSeed)SeedS);
      else
        ChiperErrorCode =         ldmc_DualInitCipherContexts(&DualCipherContext, KeyP, (unsigned int)KeyLenP, (unsigned int)DepthP, (unsigned int)NoiseP, (ldmc_tSeed)SeedP                                                                                            );
    else
        ChiperErrorCode =              ldmc_InitCipherContext(    &CipherContext, KeyP, (unsigned int)KeyLenP, (unsigned int)DepthP, (unsigned int)NoiseP, (ldmc_tSeed)SeedP                                                                                            );
    if ( ChiperErrorCode == ldmc_ErrorCode_NoError )
    {
      HANDLE InputFileHandle;
      if ( (InputFileHandle = CreateFile(SrcFileName, GENERIC_READ, FILE_SHARE_READ | ((SrcFileIsDstFile) ? FILE_SHARE_WRITE : 0), NULL, OPEN_EXISTING, 0, INVALID_HANDLE_VALUE)) != INVALID_HANDLE_VALUE )
      {
        uint64_t InputFileSize;
        if ( GetFileSizeEx(InputFileHandle, (PLARGE_INTEGER)&InputFileSize) )
        {
          HANDLE OutputFileHandle;
          if ( (OutputFileHandle = CreateFile(DstFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, ((SrcFileIsDstFile) ? OPEN_ALWAYS : CREATE_ALWAYS), FILE_ATTRIBUTE_ARCHIVE, INVALID_HANDLE_VALUE)) != INVALID_HANDLE_VALUE )
          {
            if ( InputFileSize )
            {
              HGLOBAL MemoryHandle;
              if ( (MemoryHandle = GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, ((InputFileSize > MAX_BUF_LEN) ? MAX_BUF_LEN : (DWORD)InputFileSize) )) != NULL )
              {
                BOOL ResetNeeded = FALSE;
                DWORD MaxBufLen = (MAX_BUF_LEN / (DWORD)BlockSize) * (DWORD)BlockSize;
                do
                {
                  DWORD ToProcess = ((InputFileSize > MAX_BUF_LEN) ? MaxBufLen : (DWORD)InputFileSize);
                  DWORD ReadSize;
                  if ( ReadFile(InputFileHandle, MemoryHandle, ToProcess, &ReadSize, NULL) )
                  {
                    if ( ReadSize == ToProcess )
                    {
                      DWORD Processed = 0;
                      do
                      {
                        DWORD OneRound = ((BlockSize > (ToProcess - Processed)) ? (ToProcess - Processed) : (DWORD)BlockSize);
                        if ( ResetNeeded )
                        {
                          if ( DualRun )
                            ChiperErrorCode = ldmc_DualReSetContextsForNewBlockChain(&DualCipherContext);
                          else
                            ChiperErrorCode =      ldmc_ReSetContextForNewBlockChain(    &CipherContext);
                          if ( ChiperErrorCode != ldmc_ErrorCode_NoError ) break;
                        }
                        if ( DualRun )
                          ChiperErrorCode = pDualBlockProcessor(&DualCipherContext, ldmc_IN_PLACE( ((unsigned char *)MemoryHandle) + Processed ), OneRound);
                        else
                          ChiperErrorCode =     pBlockProcessor(    &CipherContext, ldmc_IN_PLACE( ((unsigned char *)MemoryHandle) + Processed ), OneRound);
                        if ( ChiperErrorCode != ldmc_ErrorCode_NoError ) break;
                        if ( ResetPerBlock ) ResetNeeded = TRUE;
                        Processed += OneRound;
                      } while ( Processed < ToProcess );
                      if ( ChiperErrorCode == ldmc_ErrorCode_NoError )
                      {
                        DWORD WriteSize;
                        if ( WriteFile(OutputFileHandle, MemoryHandle, ToProcess, &WriteSize, NULL) )
                        {
                          if ( WriteSize != ToProcess )
                          {
                            RetVal = ERROR_CODE_FILE_WRITE_ERROR;
                            break;
                          }
                        }
                        else
                        {
                          RetVal = ERROR_CODE_FILE_WRITE_ERROR;
                          break;
                        }
                      }
                      else
                      {
                        RetVal = TranslateCipherError(ChiperErrorCode);
                        break;
                      }
                    }
                    else
                    {
                      RetVal = ERROR_CODE_FILE_READ_ERROR;
                      break;
                    }
                  }
                  else
                  {
                    RetVal = ERROR_CODE_FILE_READ_ERROR;
                    break;
                  }
                  InputFileSize -= ToProcess;
                } while ( InputFileSize );
                GlobalFree(MemoryHandle);
              }
              else
              {
                RetVal = ERROR_CODE_MEMORY_ALLOCATION_ERROR;
              }
            }
            CloseHandle(OutputFileHandle);
          }
          else
          {
            RetVal = ERROR_CODE_DST_FILE_OPEN_ERROR;
          }
        }
        else
        {
          RetVal = ERROR_CODE_GETFILESIZEEX_ERROR;
        }
        CloseHandle(InputFileHandle);
      }
      else
      {
        RetVal = ERROR_CODE_SRC_FILE_OPEN_ERROR;
      }
    }
    else
    {
      RetVal = TranslateCipherError(ChiperErrorCode);
    }
  }

  return VisualizeReturnValue( RetVal );
}



int TranslateCipherError(ldmc_tErrorCode ErrorCode)
{
  int RetVal = ERROR_CODE_CIPHER_UNKNOWN_ERROR;
  switch ( ErrorCode )
  {
    case ldmc_ErrorCode_ldmc_tByte_SizeNot1:
      RetVal = ERROR_CODE_CIPHER_TBYTE_SIZE_NOT_1_ERROR;
      break;

    case ldmc_ErrorCode_ldmc_tDial_TooShort:
      RetVal = ERROR_CODE_CIPHER_TDIAL_TOO_SHORT_ERROR;
      break;

    case ldmc_ErrorCode_BlockProcessorIsNULL:
      RetVal = ERROR_CODE_CIPHER_BLOCK_PROCESSOR_IS_NULL_ERROR;
      break;

    case ldmc_ErrorCode_ContextIsNULL:
      RetVal = ERROR_CODE_CIPHER_CONTEXT_IS_NULL_ERROR;
      break;

    case ldmc_ErrorCode_KeyBufIsNULL:
      RetVal = ERROR_CODE_CIPHER_KEY_BUF_IS_NULL_ERROR;
      break;

    case ldmc_ErrorCode_WrongKeyLen:
      RetVal = ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR;
      break;

    case ldmc_ErrorCode_WrongDepth:
      RetVal = ERROR_CODE_CIPHER_WRONG_DEPTH_ERROR;
      break;

    case ldmc_ErrorCode_WrongNoise:
      RetVal = ERROR_CODE_CIPHER_WRONG_NOISE_ERROR;
      break;

    case ldmc_ErrorCode_SrcIsNULL:
      RetVal = ERROR_CODE_CIPHER_SRC_IS_NULL_ERROR;
      break;

    case ldmc_ErrorCode_DstIsNULL:
      RetVal = ERROR_CODE_CIPHER_DST_IS_NULL_ERROR;
      break;
  }

  return RetVal;
}



int VisualizeReturnValue(int ReturnValue)
{
  switch ( ReturnValue )
  {
    case ERROR_CODE_COMMAND_LINE_ERROR:
      {
        char PathAndFileName[MAX_PATH], *FileName;

        FileName = PathAndFileName + GetModuleFileName(NULL, PathAndFileName, sizeof(PathAndFileName));
        while( FileName > PathAndFileName )
        {
          if( FileName[-1] == '\\' ) break;
          FileName--;
        }

        printf("Command line error!\n");
        printf("Usage:\n");
        printf("\n");
        printf("  %s InputFileName OutputFileName|* Mode Key [Depth [Noise [Seed [Key2 [Depth2 [Noise2 [Seed2]]]]]]]\n", FileName);
        printf("    Mode:\n");
        printf("      e:1[,BlockMode] - Encryption mode (normal)\n");
        printf("      d:1[,BlockMode] - Decryption mode (normal)\n");
        printf("      e:2[,BlockMode] - Dual Encryption mode\n");
        printf("      d:2[,BlockMode] - Dual Decryption mode\n");
        printf("      BlockMode:\n");
        printf("        Linked Block Mode (Block Chain):\n");
        printf("        fwd:BlockSize - BlockSize for forward encryption/decryption\n");
        printf("        bwd:BlockSize - BlockSize for backward encryption/decryption\n");
        printf("        bid:BlockSize - BlockSize for bidirectional dual encryption/decryption\n");
        printf("        dib:BlockSize - BlockSize for reverse bidirectional dual encryption/decryption\n");
        printf("        Independent Block Mode (Random Access):\n");
        printf("        fwd/BlockSize - BlockSize for forward encryption/decryption\n");
        printf("        bwd/BlockSize - BlockSize for backward encryption/decryption\n");
        printf("        bid/BlockSize - BlockSize for bidirectional dual encryption/decryption\n");
        printf("        dib/BlockSize - BlockSize for reverse bidirectional dual encryption/decryption\n");
        printf("          BlockSize:\n");
        printf("            1 ... %u\n", MAX_BUF_LEN);
        printf("            default: %u\n", MAX_BUF_LEN);
        printf("        default: fwd:%u\n", MAX_BUF_LEN);
        printf("    Key:\n");
        printf("      p:PassPhrase  - Primary PassPhrase for encryption/decryption\n");
        printf("      f:KeyFileName - Primary KeyFileName for encryption/decryption\n");
        printf("      KeyLen: %u ... %u\n", ldmc_KEY_LEN_MIN, ldmc_KEY_LEN_MAX);
        printf("    Depth:\n");
        printf("      %u ... %u - Primary Depth for encryption/decryption\n", ldmc_DEPTH_MIN, ldmc_DEPTH_MAX);
        printf("      default: %u\n", DEFAULT_Depth);
        printf("    Noise:\n");
        printf("      %u ... %u - Primary Noise for encryption/decryption\n", ldmc_NOISE_MIN, ldmc_NOISE_MAX);
        printf("      default: %u\n", DEFAULT_Noise);
        printf("    Seed:\n");
        printf("      0 ... %llu - Primary Seed for encryption/decryption\n", ~(0xFFFFFFFFFFFFFFFFULL << (sizeof(ldmc_tSeed) << 3)));
        printf("      default: %u\n", DEFAULT_Seed);
        printf("    Key2:\n");
        printf("      p:PassPhrase  - Secondary PassPhrase for dual encryption/decryption\n");
        printf("      f:KeyFileName - Secondary KeyFileName for dual encryption/decryption\n");
        printf("      KeyLen: %u ... %u\n", ldmc_KEY_LEN_MIN, ldmc_KEY_LEN_MAX);
        printf("      Note: If this argument is specified, dual encryption/decryption is\n");
        printf("        initialized in \"detailed\" mode, otherwise Key2 is generated from Key!\n");
        printf("    Depth2:\n");
        printf("      %u ... %u - Secondary Depth for dual encryption/decryption\n", ldmc_DEPTH_MIN, ldmc_DEPTH_MAX);
        printf("      default: Same as Depth\n");
        printf("    Noise2:\n");
        printf("      %u ... %u - Secondary Noise for dual encryption/decryption\n", ldmc_NOISE_MIN, ldmc_NOISE_MAX);
        printf("      default: Same as Noise\n");
        printf("    Seed2:\n");
        printf("      0 ... %llu - Secondary Seed for dual encryption/decryption\n", ~(0xFFFFFFFFFFFFFFFFULL << (sizeof(ldmc_tSeed) << 3)));
        printf("      default: Same as Seed\n");
        printf("    * means: OutputFileName = InputFileName\n");
        printf("\n");
        printf("  Numbers:\n");
        printf("    10  is Decimal     and is Ten\n");
        printf("    10b is Binary      and is Two\n");
        printf("    10o is Octal       and is Eight\n");
        printf("    10d is Decimal     and is Ten\n");
        printf("    10h is HexaDecimal and is SixTeen\n");
        printf("\n");
      }
      break;

    case ERROR_CODE_NO_ERROR:
      printf("Success!\n");
      break;

    case ERROR_CODE_KEY_FILE_OPEN_ERROR:
      printf("KeyFile open error!\n");
      break;

    case ERROR_CODE_SRC_FILE_OPEN_ERROR:
      printf("InputFile open error!\n");
      break;

    case ERROR_CODE_DST_FILE_OPEN_ERROR:
      printf("OutputFile open error!\n");
      break;

    case ERROR_CODE_GETFILESIZEEX_ERROR:
      printf("GetFileSizeEx error!\n");
      break;

    case ERROR_CODE_MEMORY_ALLOCATION_ERROR:
      printf("Memory allocation error!\n");
      break;

    case ERROR_CODE_FILE_READ_ERROR:
      printf("File read error!\n");
      break;

    case ERROR_CODE_FILE_WRITE_ERROR:
      printf("File write error!\n");
      break;

    case ERROR_CODE_CIPHER_UNKNOWN_ERROR:
      printf("Cipher Error: Unknown error!\n");
      break;

    case ERROR_CODE_CIPHER_TBYTE_SIZE_NOT_1_ERROR:
      printf("Cipher Error: tByte is not 1 byte error!\n");
      break;

    case ERROR_CODE_CIPHER_TDIAL_TOO_SHORT_ERROR:
      printf("Cipher Error: tDial is too short error!\n");
      break;

    case ERROR_CODE_CIPHER_BLOCK_PROCESSOR_IS_NULL_ERROR:
      printf("Cipher Error: BlockProcessor is NULL error!\n");
      break;

    case ERROR_CODE_CIPHER_CONTEXT_IS_NULL_ERROR:
      printf("Cipher Error: Context is NULL error!\n");
      break;

    case ERROR_CODE_CIPHER_KEY_BUF_IS_NULL_ERROR:
      printf("Cipher Error: KeyBuf is NULL error!\n");
      break;

    case ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR:
      printf("Cipher Error: Wrong KeyLen error!\n");
      break;

    case ERROR_CODE_CIPHER_WRONG_DEPTH_ERROR:
      printf("Cipher Error: Wrong Depth error!\n");
      break;

    case ERROR_CODE_CIPHER_WRONG_NOISE_ERROR:
      printf("Cipher Error: Wrong Noise error!\n");
      break;

    case ERROR_CODE_CIPHER_SRC_IS_NULL_ERROR:
      printf("Cipher Error: Src is NULL error!\n");
      break;

    case ERROR_CODE_CIPHER_DST_IS_NULL_ERROR:
      printf("Cipher Error: Dst is NULL error!\n");
      break;

    default:
      printf("Unknown Error Occured!\n");
      break;
  }

  return ReturnValue;
}



BOOL GetNumber(char sNumber[], uint64_t *pNumber)
{
  uint64_t Num = 0, MulLim;
  DWORD NumSys = 10, d, i, l = 0;
  unsigned char c;

  while ( sNumber[l] ) l++;
  if ( !l ) return FALSE;

  l--;
  switch ( sNumber[l] | 0x20 )
  {
    case 'b':
      NumSys = 0x02;
      break;
    case 'o':
      NumSys = 0x08;
      break;
    case 'd':
      NumSys = 0x0A;
      break;
    case 'h':
      NumSys = 0x10;
      break;
    default:
      l++;
      break;
  }
  if ( !l ) return FALSE;
  MulLim = 0xFFFFFFFFFFFFFFFFULL / NumSys;

  for ( i = 0; i < l; i++ )
  {
    c = sNumber[i];
    if ( (c >= '0') && (c <= '9') )
      d = c - '0';
    else
    {
      c |= 0x20;
      if ( (c >= 'a') && (c <= 'f') )
        d = c - 'a' + 0xA;
      else
        return FALSE;
    }
    if ( d >= NumSys ) return FALSE;
    if ( Num > MulLim) return FALSE;
    Num *= NumSys;
    if ( d > 0xFFFFFFFFFFFFFFFFULL - Num) return FALSE;
    Num += d;
  }

  *pNumber = Num;
  return TRUE;
}



const char *ParseDstFileParameter(const char *SrcName, const char *DstName, BOOL *pSrcFileIsDstFile)
{
  if ( DstName[0] == '*' )
  {
    *pSrcFileIsDstFile = TRUE;
    return ( DstName[1] ) ? NULL : SrcName; 
  }

  return DstName;
}



BOOL ParseModeParameter(char sPar[], BOOL *pDeCrypt, BOOL *pDualRun, pBlockMode pMode, uint64_t *pBlockSize, BOOL *pResetPerBlock)
{
  BOOL DeCrypt = FALSE;
  BOOL DualRun = FALSE;

  switch ( sPar[0] | 0x20 )
  {
    case 'd':
      DeCrypt = TRUE;
    case 'e':
      break;
    default:
      return FALSE;
  }
  if ( sPar[1] != ':' ) return FALSE;
  switch ( sPar[2] )
  {
    case '2':
      DualRun = TRUE;
    case '1':
      break;
    default:
      return FALSE;
  }
  if ( sPar[3] == ',' )
  {
    tBlockMode Mode                 ;
    uint64_t   BlockSize            ;
    BOOL       ResetPerBlock = FALSE;

    switch ( sPar[4] | 0x20 )
    {
      case 'f':
        if ( (sPar[5] | 0x20) != 'w' ) return FALSE;
        if ( (sPar[6] | 0x20) != 'd' ) return FALSE;
        Mode = BLOCK_FWD;
        break;
      case 'b':
        if ( (sPar[6] | 0x20) != 'd' ) return FALSE;
        switch ( sPar[5] | 0x20 )
        {
          case 'w':
            Mode = BLOCK_BWD;
            break;
          case 'i':
            Mode = BLOCK_BID;
            break;
          default:
            return FALSE;
        }
        break;
      case 'd':
        if ( (sPar[5] | 0x20) != 'i' ) return FALSE;
        if ( (sPar[6] | 0x20) != 'b' ) return FALSE;
        Mode = BLOCK_DIB;
        break;
      default:
        return FALSE;
    }
    switch ( sPar[7] )
    {
      case '/':
        ResetPerBlock = TRUE;
        break;
      case ':':
        break;
      default:
        return FALSE;
    }
    if ( !GetNumber(sPar + 8, &BlockSize) ) return FALSE;
    if (( BlockSize < 1 ) || ( BlockSize > MAX_BUF_LEN )) return FALSE;

    *pMode          = Mode         ;
    *pBlockSize     = BlockSize    ;
    *pResetPerBlock = ResetPerBlock;
  }
  else if ( sPar[3] ) return FALSE;

  *pDeCrypt = DeCrypt;
  *pDualRun = DualRun;

  return TRUE;
}



const char *ParseKeyParameter(char sPar[], BOOL *pKeyFile)
{
  BOOL KeyFile = FALSE;

  switch ( sPar[0] | 0x20 )
  {
    case 'f':
      KeyFile = TRUE;
    case 'p':
      break;
    default:
      return NULL;
  }
  if ( sPar[1] != ':' ) return NULL;

  *pKeyFile = KeyFile;

  return sPar + 2;
}



BOOL ParseDepthParameter(char sPar[], uint64_t *pDepth)
{
  uint64_t Depth;

  if ( !GetNumber(sPar, &Depth) ) return FALSE;
  if (( Depth < ldmc_DEPTH_MIN ) || ( Depth > ldmc_DEPTH_MAX )) return FALSE;

  *pDepth = Depth;

  return TRUE;
}



BOOL ParseNoiseParameter(char sPar[], uint64_t *pNoise)
{
  uint64_t Noise;

  if ( !GetNumber(sPar, &Noise) ) return FALSE;
  if (( Noise < ldmc_NOISE_MIN ) || ( Noise > ldmc_NOISE_MAX )) return FALSE;

  *pNoise = Noise;

  return TRUE;
}



BOOL ParseSeedParameter(char sPar[], uint64_t *pSeed)
{
  uint64_t Seed;

  if ( !GetNumber(sPar, &Seed) ) return FALSE;
  if ( Seed & (0xFFFFFFFFFFFFFFFFULL << (sizeof(ldmc_tSeed) << 3)) ) return FALSE;

  *pSeed = Seed;

  return TRUE;
}



int LoadKey(BOOL KeyFile, const char KeyPar[], ldmc_tByte Key[], uint64_t *pKeyLen)
{
  int RetVal = ERROR_CODE_NO_ERROR;
  uint64_t KeyLen = 0;

  if ( KeyFile )
  {
    HANDLE KeyFileHandle;
    if ( (KeyFileHandle = CreateFile(KeyPar, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, INVALID_HANDLE_VALUE)) != INVALID_HANDLE_VALUE )
    {
      if ( GetFileSizeEx(KeyFileHandle, (PLARGE_INTEGER)&KeyLen) )
      {
        if (( KeyLen >= ldmc_KEY_LEN_MIN ) && ( KeyLen <= ldmc_KEY_LEN_MAX ))
        {
          DWORD ReadSize;
          if ( ReadFile(KeyFileHandle, Key, (DWORD)KeyLen, &ReadSize, NULL) )
          {
            if ( ReadSize != KeyLen )
            {
              RetVal = ERROR_CODE_FILE_READ_ERROR;
            }
          }
          else
          {
            RetVal = ERROR_CODE_FILE_READ_ERROR;
          }
        }
        else
        {
          RetVal = ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR;
        }
      }
      else
      {
        RetVal = ERROR_CODE_GETFILESIZEEX_ERROR;
      }
      CloseHandle(KeyFileHandle);
    }
    else
    {
      RetVal = ERROR_CODE_KEY_FILE_OPEN_ERROR;
    }
  }
  else
  {
    while ( KeyPar[KeyLen] )
    {
      if ( KeyLen < ldmc_KEY_LEN_MAX )
      {
        Key[KeyLen] = KeyPar[KeyLen];
        KeyLen++;
      }
      else
      {
        RetVal = ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR;
        break;
      }
    }
    if ( KeyLen < ldmc_KEY_LEN_MIN ) RetVal = ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR;
  }

  if ( RetVal == ERROR_CODE_NO_ERROR ) *pKeyLen = KeyLen;

  return RetVal;
}



