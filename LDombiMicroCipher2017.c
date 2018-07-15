#include "LDombiMicroCipher2017.h"



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
static ldmc_tByte ldmc_EnCryptByte8(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte7(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte6(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte5(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
static ldmc_tByte ldmc_EnCryptByte4(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte3(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
static ldmc_tByte ldmc_EnCryptByte2(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte1(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
static ldmc_tByte ldmc_EnCryptByte (ldmc_pCipherContext pContext, ldmc_tByte Input);

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
static ldmc_tByte ldmc_DeCryptByte8(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte7(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte6(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte5(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
static ldmc_tByte ldmc_DeCryptByte4(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte3(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
static ldmc_tByte ldmc_DeCryptByte2(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte1(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
static ldmc_tByte ldmc_DeCryptByte (ldmc_pCipherContext pContext, ldmc_tByte Input);

#endif



static ldmc_tErrorCode ldmc_CheckConfig(void)
{
  unsigned int i, t = ((unsigned int)ldmc_KEY_LEN_MAX) - 1;

  if( sizeof(ldmc_tByte) != 1 ) return ldmc_ErrorCode_ldmc_tByte_SizeNot1;
  for( i = 0; i < sizeof(ldmc_tDial); i++ ) t >>= 8;
  if( t ) return ldmc_ErrorCode_ldmc_tDial_TooShort;

  return ldmc_ErrorCode_NoError;
}



static ldmc_tErrorCode ldmc_CachingCheckConfig(void)
{
  static ldmc_tErrorCode RetVal = ldmc_ErrorCode_NoError;
  static enum { No, Yes } Checked = No;

  if( Checked != Yes )
  {
    RetVal = ldmc_CheckConfig();
    Checked = Yes;
  }

  return RetVal;
}



ldmc_tErrorCode ldmc_InitCipherContext(ldmc_pCipherContext pContext, ldmc_tByte KeyBuf[], unsigned int KeyLen, unsigned int Depth, unsigned int Noise, ldmc_tSeed Seed)
{
  ldmc_tErrorCode ErrorCode = ldmc_CachingCheckConfig();
  register unsigned int i, q = 0, r = 1;
  register ldmc_pByte Key;
  register ldmc_pDial Dials;
  register ldmc_tSeed t;
  register ldmc_tByte IMask;
  register ldmc_tByte Mask0 = 0, Mask1 = 0, Mask2 = 0, Mask3 = 0;

  if( ErrorCode != ldmc_ErrorCode_NoError ) return ErrorCode;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !KeyBuf ) return ldmc_ErrorCode_KeyBufIsNULL;
  if(( KeyLen < ldmc_KEY_LEN_MIN ) || ( KeyLen > ldmc_KEY_LEN_MAX )) return ldmc_ErrorCode_WrongKeyLen;
  if(( Depth < ldmc_DEPTH_MIN ) || ( Depth > ldmc_DEPTH_MAX )) return ldmc_ErrorCode_WrongDepth;
  if(( Noise < ldmc_NOISE_MIN ) || ( Noise > ldmc_NOISE_MAX )) return ldmc_ErrorCode_WrongNoise;

  Key   = pContext->Key  ;
  Dials = pContext->Dials;

  Mask0 += (ldmc_tByte)((((1 + (unsigned int)(IMask = (((unsigned int)1) << Noise) - 1)) * r) % 251 + 1) & 0xFFU);
  r = (r * 257) % 251;

  for( i = 0; i < KeyLen; i++ )
  {
    Mask3 = Mask2;
    Mask2 = Mask1;
    Mask1 = Mask0;
    Mask0 += (ldmc_tByte)((((1 + (unsigned int)(Key[i] = KeyBuf[i])) * r) % 251 + 1) & 0xFFU);
    r = (r * 257) % 251;
  }

  t = Seed;
  for( i = 0; i < Depth; i++ )
  {
    q += (unsigned int)(Key[i % KeyLen]) + (unsigned int)(t % KeyLen) + (i / KeyLen) + 1;
    Dials[i] = (ldmc_tDial)(q % KeyLen);
    q /= KeyLen;
    t /= KeyLen;
  }
  for( i = Depth; i < KeyLen; i++ )
  {
    unsigned int d = i % Depth;
    q += (unsigned int)(Key[i]) + (unsigned int)(Dials[d]) + 1;
    Dials[d] = (ldmc_tDial)(q % KeyLen);
    q /= KeyLen;
  }
  if( Depth <= (ldmc_DIAL_BUF_LEN >> 1) )
  {
    register ldmc_pDial Reset = Dials + Depth;

    for( i = 0; i < Depth; i++ ) Reset[i] = Dials[i];
  }

  {
    pContext->BackUpSet.Mask0 = Mask0;
    pContext->BackUpSet.Mask1 = Mask1;
    pContext->BackUpSet.Mask2 = Mask2;
    pContext->BackUpSet.Mask3 = Mask3;

    pContext->KeyLen = KeyLen;
    pContext->Depth  = Depth ;
    pContext->Seed   = Seed  ;
    pContext->IMask  = IMask ;
    pContext->Index  = 0     ;
    pContext->LinkP  = 0     ;
    pContext->LinkC  = 0     ;
    for( i = 0; (i & ~(unsigned int)IMask) == 0; i++ )
    {
      pContext->MaskSets[i].Mask0 = Mask0;
      pContext->MaskSets[i].Mask1 = Mask1;
      pContext->MaskSets[i].Mask2 = Mask2;
      pContext->MaskSets[i].Mask3 = Mask3;
    }
  }

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  switch( Depth )
  {
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
    case 8:
      pContext->pEnCryptByte = ldmc_EnCryptByte8;
      pContext->pDeCryptByte = ldmc_DeCryptByte8;
      break;
    case 7:
      pContext->pEnCryptByte = ldmc_EnCryptByte7;
      pContext->pDeCryptByte = ldmc_DeCryptByte7;
      break;
    case 6:
      pContext->pEnCryptByte = ldmc_EnCryptByte6;
      pContext->pDeCryptByte = ldmc_DeCryptByte6;
      break;
    case 5:
      pContext->pEnCryptByte = ldmc_EnCryptByte5;
      pContext->pDeCryptByte = ldmc_DeCryptByte5;
      break;
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
    case 4:
      pContext->pEnCryptByte = ldmc_EnCryptByte4;
      pContext->pDeCryptByte = ldmc_DeCryptByte4;
      break;
    case 3:
      pContext->pEnCryptByte = ldmc_EnCryptByte3;
      pContext->pDeCryptByte = ldmc_DeCryptByte3;
      break;
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
    case 2:
      pContext->pEnCryptByte = ldmc_EnCryptByte2;
      pContext->pDeCryptByte = ldmc_DeCryptByte2;
      break;
    case 1:
      pContext->pEnCryptByte = ldmc_EnCryptByte1;
      pContext->pDeCryptByte = ldmc_DeCryptByte1;
      break;
#endif
    default:
      pContext->pEnCryptByte = ldmc_EnCryptByte ;
      pContext->pDeCryptByte = ldmc_DeCryptByte ;
      break;
  }
#endif

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_ReSetContextForNewBlockChain(ldmc_pCipherContext pContext)
{
  register unsigned int i;
  register ldmc_pDial Dials;
  register unsigned int Depth;
  register ldmc_tByte IMask;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;

  Dials  = pContext->Dials ;
  Depth  = pContext->Depth ;
  IMask  = pContext->IMask;
  if( Depth <= (ldmc_DIAL_BUF_LEN >> 1) )
  {
    register ldmc_pDial Reset = Dials + Depth;

    for( i = 0; i < Depth; i++ ) Dials[i] = Reset[i];
  }
  else
  {
    register unsigned int q = 0;
    register ldmc_pByte   Key    = pContext->Key   ;
    register unsigned int KeyLen = pContext->KeyLen;
    register ldmc_tSeed   t      = pContext->Seed  ;

    for( i = 0; i < Depth; i++ )
    {
      q += (unsigned int)(Key[i % KeyLen]) + (unsigned int)(t % KeyLen) + (i / KeyLen) + 1;
      Dials[i] = (ldmc_tDial)(q % KeyLen);
      q /= KeyLen;
      t /= KeyLen;
    }
    for( i = Depth; i < KeyLen; i++ )
    {
      unsigned int d = i % Depth;
      q += (unsigned int)(Key[i]) + (unsigned int)(Dials[d]) + 1;
      Dials[d] = (ldmc_tDial)(q % KeyLen);
      q /= KeyLen;
    }
  }

  {
    register ldmc_tByte Mask0 = pContext->BackUpSet.Mask0;
    register ldmc_tByte Mask1 = pContext->BackUpSet.Mask1;
    register ldmc_tByte Mask2 = pContext->BackUpSet.Mask2;
    register ldmc_tByte Mask3 = pContext->BackUpSet.Mask3;

    pContext->Index = 0;
    pContext->LinkP = 0;
    pContext->LinkC = 0;
    for( i = 0; (i & ~(unsigned int)IMask) == 0; i++ )
    {
      pContext->MaskSets[i].Mask0 = Mask0;
      pContext->MaskSets[i].Mask1 = Mask1;
      pContext->MaskSets[i].Mask2 = Mask2;
      pContext->MaskSets[i].Mask3 = Mask3;
    }
  }

  return ldmc_ErrorCode_NoError;
}



#define ldmc_ScrambleTheInternalStates( PreFixC, PreFixM, PByte, CByte ) \
  PreFixC##Index = (Index + 1) & (PreFixC##IMask);                       \
  PreFixC##LinkP = LinkP + PByte;                                        \
  PreFixC##LinkC = LinkC - CByte;                                        \
  PreFixM##Mask0 = PByte ^ CByte;                                        \
  PreFixM##Mask1 = Mask0 + PByte;                                        \
  PreFixM##Mask2 = Mask1 ^ CByte;                                        \
  PreFixM##Mask3 = Mask2 + Mask3;                                        \



#define ldmc_RotateTheDialsCore( D )                         \
    {                                                        \
      register ldmc_tDial Dial;                              \
      register unsigned int KeyLen_1 = pContext->KeyLen - 1; \
                                                             \
      for( i = 0; i < D; i++ )                               \
      {                                                      \
        if( (Dial = Dials[i]) < KeyLen_1 )                   \
        {                                                    \
          Dials[i] = Dial + 1;                               \
          break;                                             \
        }                                                    \
        Dials[i] = 0;                                        \
      }                                                      \
    }                                                        \

#define ldmc_RotateTheDialsCoreI( D )                        \
  {                                                          \
    register unsigned int i;                                 \
                                                             \
    ldmc_RotateTheDialsCore( D )                             \
  }                                                          \



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) <= 0 )
static void ldmc_RotateTheDials(ldmc_pCipherContext pContext)
{
  register ldmc_pDial   Dials = pContext->Dials;
  register unsigned int Depth = pContext->Depth;

  ldmc_RotateTheDialsCoreI( Depth )
}
#endif



static ldmc_tByte ldmc_EnCodeTable[] =
{
  0x29U, 0x6CU, 0xF0U, 0xBEU, 0x11U, 0xA5U, 0xE9U, 0xE6U, 0xB6U, 0x0BU, 0x32U, 0xDFU, 0x69U, 0x40U, 0x2AU, 0x09U,
  0x7CU, 0xF8U, 0x4AU, 0xEFU, 0x42U, 0x25U, 0xACU, 0xA7U, 0x45U, 0x99U, 0xBFU, 0xBAU, 0x7BU, 0xA2U, 0x1AU, 0x8EU,
  0xF2U, 0xBDU, 0x6AU, 0x19U, 0xAAU, 0x16U, 0x26U, 0x96U, 0xE1U, 0xC2U, 0x5DU, 0x67U, 0x5CU, 0x1CU, 0x1BU, 0xE4U,
  0xD4U, 0x31U, 0x03U, 0xD8U, 0x1FU, 0x60U, 0x37U, 0xFBU, 0x9CU, 0xF4U, 0x08U, 0xF3U, 0xD2U, 0x8DU, 0x63U, 0x89U,
  0x80U, 0x9EU, 0x92U, 0x51U, 0x77U, 0x20U, 0x8FU, 0xAFU, 0x5AU, 0xC7U, 0xE5U, 0xCDU, 0x5BU, 0xC0U, 0x0AU, 0x0DU,
  0x85U, 0x27U, 0x6DU, 0x56U, 0x0EU, 0x41U, 0x3BU, 0xA8U, 0xECU, 0x88U, 0x14U, 0x9BU, 0x2FU, 0x79U, 0x35U, 0xCAU,
  0xC1U, 0x1DU, 0x24U, 0x61U, 0xFDU, 0xC3U, 0x28U, 0xD9U, 0x64U, 0xC6U, 0x38U, 0x7EU, 0x01U, 0x4FU, 0x6EU, 0x47U,
  0xFAU, 0x66U, 0x30U, 0x5EU, 0x4CU, 0x07U, 0xEEU, 0x90U, 0x6BU, 0x7DU, 0x68U, 0x23U, 0x65U, 0x12U, 0xF7U, 0xBCU,
  0x8AU, 0xE3U, 0x13U, 0x3EU, 0xA9U, 0xA6U, 0x84U, 0x5FU, 0x44U, 0xB9U, 0xA3U, 0xE7U, 0x49U, 0xDAU, 0x7FU, 0xE0U,
  0x78U, 0x4BU, 0xD1U, 0x93U, 0x4DU, 0xBBU, 0x9FU, 0x9DU, 0x83U, 0x8BU, 0xEBU, 0xCFU, 0x00U, 0x39U, 0x76U, 0x10U,
  0x59U, 0xF5U, 0xDDU, 0xD5U, 0x3CU, 0x43U, 0xABU, 0x72U, 0xF1U, 0xDEU, 0xB1U, 0xC9U, 0x9AU, 0xC8U, 0x0CU, 0x94U,
  0xD7U, 0xAEU, 0x2CU, 0xFEU, 0xF9U, 0x21U, 0xB4U, 0x58U, 0xE8U, 0x7AU, 0x91U, 0xDCU, 0x8CU, 0xFCU, 0x73U, 0x1EU,
  0x22U, 0xD3U, 0x36U, 0xB0U, 0x75U, 0x2DU, 0x52U, 0xE2U, 0x82U, 0x71U, 0xA4U, 0x3FU, 0x2BU, 0xEAU, 0x55U, 0x02U,
  0xF6U, 0xB7U, 0x4EU, 0xA0U, 0xCBU, 0x53U, 0xD0U, 0x97U, 0xCEU, 0x3AU, 0x57U, 0xA1U, 0xCCU, 0x48U, 0x18U, 0xFFU,
  0xB3U, 0xD6U, 0x86U, 0x2EU, 0x04U, 0x33U, 0x17U, 0x46U, 0x3DU, 0x54U, 0x15U, 0x50U, 0xADU, 0x6FU, 0xDBU, 0x06U,
  0x81U, 0xEDU, 0x70U, 0x74U, 0x34U, 0xC4U, 0x98U, 0x0FU, 0xB2U, 0x95U, 0x87U, 0xC5U, 0x05U, 0x62U, 0xB5U, 0xB8U
};



#define ldmc_EnterEnCryption( PByte ) PByte += LinkC;

#define ldmc_LeaveEnCryption( CByte ) CByte -= LinkP;



#define ldmc_EnCryptByteCore( I )  \
    Coder = Key[Dials[I]];         \
    Work = ldmc_EnCodeTable[Work]; \
    Work ^=        ~Mask0;         \
    Work += Coder        ;         \
    Work ^= Coder & Mask1;         \
    Work -= Coder        ;         \
    Work ^= Coder | Mask2;         \
    Work += Coder ^ Mask3;         \



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
static ldmc_tByte ldmc_EnCryptByte8(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterEnCryption( Work )

  ldmc_EnCryptByteCore( 7 )
  ldmc_EnCryptByteCore( 6 )
  ldmc_EnCryptByteCore( 5 )
  ldmc_EnCryptByteCore( 4 )
  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_LeaveEnCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 8 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte7(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterEnCryption( Work )

  ldmc_EnCryptByteCore( 6 )
  ldmc_EnCryptByteCore( 5 )
  ldmc_EnCryptByteCore( 4 )
  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_LeaveEnCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 7 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte6(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterEnCryption( Work )

  ldmc_EnCryptByteCore( 5 )
  ldmc_EnCryptByteCore( 4 )
  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_LeaveEnCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 6 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte5(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterEnCryption( Work )

  ldmc_EnCryptByteCore( 4 )
  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_LeaveEnCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 5 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
static ldmc_tByte ldmc_EnCryptByte4(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterEnCryption( Work )

  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_LeaveEnCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 4 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte3(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterEnCryption( Work )

  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_LeaveEnCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 3 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
static ldmc_tByte ldmc_EnCryptByte2(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterEnCryption( Work )

  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_LeaveEnCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 2 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte1(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterEnCryption( Work )

  ldmc_EnCryptByteCore( 0 )

  ldmc_LeaveEnCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 1 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



static ldmc_tByte ldmc_EnCryptByte (ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte            Index = pContext->Index;
  ldmc_tByte            LinkP = pContext->LinkP;
  ldmc_tByte            LinkC = pContext->LinkC;
  ldmc_pMaskSet      pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte   Coder;
  register ldmc_tByte   Work  = Input;
  register ldmc_pByte   Key   = pContext->Key  ;
  register ldmc_pDial   Dials = pContext->Dials;
  register unsigned int Depth = pContext->Depth;
  register ldmc_tByte   Mask0 = pMaskSet->Mask0;
  register ldmc_tByte   Mask1 = pMaskSet->Mask1;
  register ldmc_tByte   Mask2 = pMaskSet->Mask2;
  register ldmc_tByte   Mask3 = pMaskSet->Mask3;
  register unsigned int c = Depth, i = Depth;

  ldmc_EnterEnCryption( Work )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
  while( c >= 8 )
  {
    ldmc_EnCryptByteCore( i - 1 )
    ldmc_EnCryptByteCore( i - 2 )
    ldmc_EnCryptByteCore( i - 3 )
    ldmc_EnCryptByteCore( i - 4 )
    ldmc_EnCryptByteCore( i - 5 )
    ldmc_EnCryptByteCore( i - 6 )
    ldmc_EnCryptByteCore( i - 7 )
    ldmc_EnCryptByteCore( i - 8 )
    i -= 8;
    c -= 8;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  2 )
  if   
#else
  while
#endif
       ( c >= 4 )
  {
    ldmc_EnCryptByteCore( i - 1 )
    ldmc_EnCryptByteCore( i - 2 )
    ldmc_EnCryptByteCore( i - 3 )
    ldmc_EnCryptByteCore( i - 4 )
    i -= 4;
    c -= 4;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  1 )
  if   
#else
  while
#endif
       ( c >= 2 )
  {
    ldmc_EnCryptByteCore( i - 1 )
    ldmc_EnCryptByteCore( i - 2 )
    i -= 2;
    c -= 2;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  if   ( c )
  {
    ldmc_EnCryptByteCore( i - 1 )
  }
#else
  while( c )
  {
    ldmc_EnCryptByteCore( --i )
    c--;
  }
#endif

  ldmc_LeaveEnCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCore( Depth )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCodeTable[] =
{
  0x9CU, 0x6CU, 0xCFU, 0x32U, 0xE4U, 0xFCU, 0xEFU, 0x75U, 0x3AU, 0x0FU, 0x4EU, 0x09U, 0xAEU, 0x4FU, 0x54U, 0xF7U,
  0x9FU, 0x04U, 0x7DU, 0x82U, 0x5AU, 0xEAU, 0x25U, 0xE6U, 0xDEU, 0x23U, 0x1EU, 0x2EU, 0x2DU, 0x61U, 0xBFU, 0x34U,
  0x45U, 0xB5U, 0xC0U, 0x7BU, 0x62U, 0x15U, 0x26U, 0x51U, 0x66U, 0x00U, 0x0EU, 0xCCU, 0xB2U, 0xC5U, 0xE3U, 0x5CU,
  0x72U, 0x31U, 0x0AU, 0xE5U, 0xF4U, 0x5EU, 0xC2U, 0x36U, 0x6AU, 0x9DU, 0xD9U, 0x56U, 0xA4U, 0xE8U, 0x83U, 0xCBU,
  0x0DU, 0x55U, 0x14U, 0xA5U, 0x88U, 0x18U, 0xE7U, 0x6FU, 0xDDU, 0x8CU, 0x12U, 0x91U, 0x74U, 0x94U, 0xD2U, 0x6DU,
  0xEBU, 0x43U, 0xC6U, 0xD5U, 0xE9U, 0xCEU, 0x53U, 0xDAU, 0xB7U, 0xA0U, 0x48U, 0x4CU, 0x2CU, 0x2AU, 0x73U, 0x87U,
  0x35U, 0x63U, 0xFDU, 0x3EU, 0x68U, 0x7CU, 0x71U, 0x2BU, 0x7AU, 0x0CU, 0x22U, 0x78U, 0x01U, 0x52U, 0x6EU, 0xEDU,
  0xF2U, 0xC9U, 0xA7U, 0xBEU, 0xF3U, 0xC4U, 0x9EU, 0x44U, 0x90U, 0x5DU, 0xB9U, 0x1CU, 0x10U, 0x79U, 0x6BU, 0x8EU,
  0x40U, 0xF0U, 0xC8U, 0x98U, 0x86U, 0x50U, 0xE2U, 0xFAU, 0x59U, 0x3FU, 0x80U, 0x99U, 0xBCU, 0x3DU, 0x1FU, 0x46U,
  0x77U, 0xBAU, 0x42U, 0x93U, 0xAFU, 0xF9U, 0x27U, 0xD7U, 0xF6U, 0x19U, 0xACU, 0x5BU, 0x38U, 0x97U, 0x41U, 0x96U,
  0xD3U, 0xDBU, 0x1DU, 0x8AU, 0xCAU, 0x05U, 0x85U, 0x17U, 0x57U, 0x84U, 0x24U, 0xA6U, 0x16U, 0xECU, 0xB1U, 0x47U,
  0xC3U, 0xAAU, 0xF8U, 0xE0U, 0xB6U, 0xFEU, 0x08U, 0xD1U, 0xFFU, 0x89U, 0x1BU, 0x95U, 0x7FU, 0x21U, 0x03U, 0x1AU,
  0x4DU, 0x60U, 0x29U, 0x65U, 0xF5U, 0xFBU, 0x69U, 0x49U, 0xADU, 0xABU, 0x5FU, 0xD4U, 0xDCU, 0x4BU, 0xD8U, 0x9BU,
  0xD6U, 0x92U, 0x3CU, 0xC1U, 0x30U, 0xA3U, 0xE1U, 0xB0U, 0x33U, 0x67U, 0x8DU, 0xEEU, 0xBBU, 0xA2U, 0xA9U, 0x0BU,
  0x8FU, 0x28U, 0xC7U, 0x81U, 0x2FU, 0x4AU, 0x07U, 0x8BU, 0xB8U, 0x06U, 0xCDU, 0x9AU, 0x58U, 0xF1U, 0x76U, 0x13U,
  0x02U, 0xA8U, 0x20U, 0x3BU, 0x39U, 0xA1U, 0xD0U, 0x7EU, 0x11U, 0xB4U, 0x70U, 0x37U, 0xBDU, 0x64U, 0xB3U, 0xDFU
};



#define ldmc_EnterDeCryption( CByte ) CByte += LinkP;

#define ldmc_LeaveDeCryption( PByte ) PByte -= LinkC;



#define ldmc_DeCryptByteCore( I )  \
    Coder = Key[Dials[I]];         \
    Work -= Coder ^ Mask3;         \
    Work ^= Coder | Mask2;         \
    Work += Coder        ;         \
    Work ^= Coder & Mask1;         \
    Work -= Coder        ;         \
    Work ^=        ~Mask0;         \
    Work = ldmc_DeCodeTable[Work]; \



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
static ldmc_tByte ldmc_DeCryptByte8(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterDeCryption( Work )

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )
  ldmc_DeCryptByteCore( 4 )
  ldmc_DeCryptByteCore( 5 )
  ldmc_DeCryptByteCore( 6 )
  ldmc_DeCryptByteCore( 7 )

  ldmc_LeaveDeCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 8 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte7(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterDeCryption( Work )

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )
  ldmc_DeCryptByteCore( 4 )
  ldmc_DeCryptByteCore( 5 )
  ldmc_DeCryptByteCore( 6 )

  ldmc_LeaveDeCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 7 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte6(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterDeCryption( Work )

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )
  ldmc_DeCryptByteCore( 4 )
  ldmc_DeCryptByteCore( 5 )

  ldmc_LeaveDeCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 6 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte5(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterDeCryption( Work )

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )
  ldmc_DeCryptByteCore( 4 )

  ldmc_LeaveDeCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 5 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
static ldmc_tByte ldmc_DeCryptByte4(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterDeCryption( Work )

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )

  ldmc_LeaveDeCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 4 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte3(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterDeCryption( Work )

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )

  ldmc_LeaveDeCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 3 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
static ldmc_tByte ldmc_DeCryptByte2(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterDeCryption( Work )

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )

  ldmc_LeaveDeCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 2 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte1(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte          Index = pContext->Index;
  ldmc_tByte          LinkP = pContext->LinkP;
  ldmc_tByte          LinkC = pContext->LinkC;
  ldmc_pMaskSet    pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask0 = pMaskSet->Mask0;
  register ldmc_tByte Mask1 = pMaskSet->Mask1;
  register ldmc_tByte Mask2 = pMaskSet->Mask2;
  register ldmc_tByte Mask3 = pMaskSet->Mask3;

  ldmc_EnterDeCryption( Work )

  ldmc_DeCryptByteCore( 0 )

  ldmc_LeaveDeCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 1 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



static ldmc_tByte ldmc_DeCryptByte (ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  ldmc_tByte            Index = pContext->Index;
  ldmc_tByte            LinkP = pContext->LinkP;
  ldmc_tByte            LinkC = pContext->LinkC;
  ldmc_pMaskSet      pMaskSet = &(pContext->MaskSets[Index]);
  register ldmc_tByte   Coder;
  register ldmc_tByte   Work  = Input;
  register ldmc_pByte   Key   = pContext->Key  ;
  register ldmc_pDial   Dials = pContext->Dials;
  register unsigned int Depth = pContext->Depth;
  register ldmc_tByte   Mask0 = pMaskSet->Mask0;
  register ldmc_tByte   Mask1 = pMaskSet->Mask1;
  register ldmc_tByte   Mask2 = pMaskSet->Mask2;
  register ldmc_tByte   Mask3 = pMaskSet->Mask3;
  register unsigned int c = Depth, i = 0;

  ldmc_EnterDeCryption( Work )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
  while( c >= 8 )
  {
    ldmc_DeCryptByteCore( i + 0 )
    ldmc_DeCryptByteCore( i + 1 )
    ldmc_DeCryptByteCore( i + 2 )
    ldmc_DeCryptByteCore( i + 3 )
    ldmc_DeCryptByteCore( i + 4 )
    ldmc_DeCryptByteCore( i + 5 )
    ldmc_DeCryptByteCore( i + 6 )
    ldmc_DeCryptByteCore( i + 7 )
    i += 8;
    c -= 8;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  2 )
  if   
#else
  while
#endif
       ( c >= 4 )
  {
    ldmc_DeCryptByteCore( i + 0 )
    ldmc_DeCryptByteCore( i + 1 )
    ldmc_DeCryptByteCore( i + 2 )
    ldmc_DeCryptByteCore( i + 3 )
    i += 4;
    c -= 4;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  1 )
  if   
#else
  while
#endif
       ( c >= 2 )
  {
    ldmc_DeCryptByteCore( i + 0 )
    ldmc_DeCryptByteCore( i + 1 )
    i += 2;
    c -= 2;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  if   ( c )
  {
    ldmc_DeCryptByteCore( i + 0 )
  }
#else
  while( c )
  {
    ldmc_DeCryptByteCore( i++ )
    c--;
  }
#endif

  ldmc_LeaveDeCryption( Work )

  ldmc_ScrambleTheInternalStates( pContext->, pMaskSet->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCore( Depth )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



ldmc_tErrorCode ldmc_EnCryptBlockFWD(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pEnCryptByte;
  #define EnCryptByte (*pEnCryptByte)
#else
  #define EnCryptByte ldmc_EnCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pEnCryptByte = pContext->pEnCryptByte;
#endif

  for( i = 0; i < rSize; i++ )
  {
    *(pcDst++) = EnCryptByte(pContext, *(pcSrc++));
  }

  return ldmc_ErrorCode_NoError;
  #undef EnCryptByte
}



ldmc_tErrorCode ldmc_DeCryptBlockFWD(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pDeCryptByte;
  #define DeCryptByte (*pDeCryptByte)
#else
  #define DeCryptByte ldmc_DeCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pDeCryptByte = pContext->pDeCryptByte;
#endif

  for( i = 0; i < rSize; i++ )
  {
    *(pcDst++) = DeCryptByte(pContext, *(pcSrc++));
  }

  return ldmc_ErrorCode_NoError;
  #undef DeCryptByte
}



ldmc_tErrorCode ldmc_EnCryptBlockBWD(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pEnCryptByte;
  #define EnCryptByte (*pEnCryptByte)
#else
  #define EnCryptByte ldmc_EnCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pEnCryptByte = pContext->pEnCryptByte;
#endif

  pcSrc += Size;
  pcDst += Size;

  for( i = 0; i < rSize; i++ )
  {
    *(--pcDst) = EnCryptByte(pContext, *(--pcSrc));
  }

  return ldmc_ErrorCode_NoError;
  #undef EnCryptByte
}



ldmc_tErrorCode ldmc_DeCryptBlockBWD(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pDeCryptByte;
  #define DeCryptByte (*pDeCryptByte)
#else
  #define DeCryptByte ldmc_DeCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pDeCryptByte = pContext->pDeCryptByte;
#endif

  pcSrc += Size;
  pcDst += Size;

  for( i = 0; i < rSize; i++ )
  {
    *(--pcDst) = DeCryptByte(pContext, *(--pcSrc));
  }

  return ldmc_ErrorCode_NoError;
  #undef DeCryptByte
}



ldmc_tErrorCode ldmc_ReSetContextForNewBlockChainAndCall(ldmc_pBlockProcessor pBlockProcessor, ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pBlockProcessor ) return ldmc_ErrorCode_BlockProcessorIsNULL;

  if( !pSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pDst ) return ldmc_ErrorCode_DstIsNULL;

  if( (ErrorCode = ldmc_ReSetContextForNewBlockChain(pContext                  )) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode =                (*pBlockProcessor)(pContext, pSrc, pDst, Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_CallAndReSetContextForNewBlockChain(ldmc_pBlockProcessor pBlockProcessor, ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pBlockProcessor ) return ldmc_ErrorCode_BlockProcessorIsNULL;

  if( !pSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pDst ) return ldmc_ErrorCode_DstIsNULL;

  if( (ErrorCode =                (*pBlockProcessor)(pContext, pSrc, pDst, Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_ReSetContextForNewBlockChain(pContext                  )) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_DualInitCipherContexts(ldmc_pDualCipherContext pContext, ldmc_tByte KeyBuf[], unsigned int KeyLen, unsigned int Depth, unsigned int Noise, ldmc_tSeed Seed)
{
  ldmc_tErrorCode ErrorCode;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( KeyLen <= ldmc_KEY_LEN_MIN ) return ldmc_ErrorCode_WrongKeyLen;

  if( (ErrorCode = ldmc_InitCipherContext(&(pContext->P), KeyBuf + 0, KeyLen - 0, Depth, Noise, Seed)) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_InitCipherContext(&(pContext->S), KeyBuf + 1, KeyLen - 1, Depth, Noise, Seed)) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_DualDetailedInitCipherContexts(ldmc_pDualCipherContext pContext, ldmc_tByte KeyBufP[], unsigned int KeyLenP, unsigned int DepthP, unsigned int NoiseP, ldmc_tSeed SeedP, ldmc_tByte KeyBufS[], unsigned int KeyLenS, unsigned int DepthS, unsigned int NoiseS, ldmc_tSeed SeedS)
{
  ldmc_tErrorCode ErrorCode;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;

  if( (ErrorCode = ldmc_InitCipherContext(&(pContext->P), KeyBufP, KeyLenP, DepthP, NoiseP, SeedP)) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_InitCipherContext(&(pContext->S), KeyBufS, KeyLenS, DepthS, NoiseS, SeedS)) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_DualReSetContextsForNewBlockChain(ldmc_pDualCipherContext pContext)
{
  ldmc_tErrorCode ErrorCode;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;

  if( (ErrorCode = ldmc_ReSetContextForNewBlockChain(&(pContext->P))) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_ReSetContextForNewBlockChain(&(pContext->S))) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_DualEnCryptBlockFWD(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pEnCryptByteP, pEnCryptByteS;
  #define EnCryptByteP (*pEnCryptByteP)
  #define EnCryptByteS (*pEnCryptByteS)
#else
  #define EnCryptByteP ldmc_EnCryptByte
  #define EnCryptByteS ldmc_EnCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pEnCryptByteP = pContext->P.pEnCryptByte;
  pEnCryptByteS = pContext->S.pEnCryptByte;
#endif

  for( i = 0; i < rSize; i++ )
  {
    *(pcDst++) = EnCryptByteS(&(pContext->S), EnCryptByteP(&(pContext->P), *(pcSrc++)));
  }

  return ldmc_ErrorCode_NoError;
  #undef EnCryptByteS
  #undef EnCryptByteP
}



ldmc_tErrorCode ldmc_DualDeCryptBlockFWD(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pDeCryptByteP, pDeCryptByteS;
  #define DeCryptByteP (*pDeCryptByteP)
  #define DeCryptByteS (*pDeCryptByteS)
#else
  #define DeCryptByteP ldmc_DeCryptByte
  #define DeCryptByteS ldmc_DeCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pDeCryptByteP = pContext->P.pDeCryptByte;
  pDeCryptByteS = pContext->S.pDeCryptByte;
#endif

  for( i = 0; i < rSize; i++ )
  {
    *(pcDst++) = DeCryptByteP(&(pContext->P), DeCryptByteS(&(pContext->S), *(pcSrc++)));
  }

  return ldmc_ErrorCode_NoError;
  #undef DeCryptByteS
  #undef DeCryptByteP
}



ldmc_tErrorCode ldmc_DualEnCryptBlockBWD(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pEnCryptByteP, pEnCryptByteS;
  #define EnCryptByteP (*pEnCryptByteP)
  #define EnCryptByteS (*pEnCryptByteS)
#else
  #define EnCryptByteP ldmc_EnCryptByte
  #define EnCryptByteS ldmc_EnCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pEnCryptByteP = pContext->P.pEnCryptByte;
  pEnCryptByteS = pContext->S.pEnCryptByte;
#endif

  pcSrc += Size;
  pcDst += Size;

  for( i = 0; i < rSize; i++ )
  {
    *(--pcDst) = EnCryptByteS(&(pContext->S), EnCryptByteP(&(pContext->P), *(--pcSrc)));
  }

  return ldmc_ErrorCode_NoError;
  #undef EnCryptByteS
  #undef EnCryptByteP
}



ldmc_tErrorCode ldmc_DualDeCryptBlockBWD(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pDeCryptByteP, pDeCryptByteS;
  #define DeCryptByteP (*pDeCryptByteP)
  #define DeCryptByteS (*pDeCryptByteS)
#else
  #define DeCryptByteP ldmc_DeCryptByte
  #define DeCryptByteS ldmc_DeCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pDeCryptByteP = pContext->P.pDeCryptByte;
  pDeCryptByteS = pContext->S.pDeCryptByte;
#endif

  pcSrc += Size;
  pcDst += Size;

  for( i = 0; i < rSize; i++ )
  {
    *(--pcDst) = DeCryptByteP(&(pContext->P), DeCryptByteS(&(pContext->S), *(--pcSrc)));
  }

  return ldmc_ErrorCode_NoError;
  #undef DeCryptByteS
  #undef DeCryptByteP
}



ldmc_tErrorCode ldmc_DualEnCryptBlockBID(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;

  if( (ErrorCode = ldmc_EnCryptBlockFWD(&(pContext->P),          pSrc, pDst , Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_EnCryptBlockBWD(&(pContext->S), ldmc_IN_PLACE( pDst), Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_DualDeCryptBlockBID(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;

  if( (ErrorCode = ldmc_DeCryptBlockBWD(&(pContext->S),          pSrc, pDst , Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_DeCryptBlockFWD(&(pContext->P), ldmc_IN_PLACE( pDst), Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_DualEnCryptBlockDIB(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;

  if( (ErrorCode = ldmc_EnCryptBlockBWD(&(pContext->P),          pSrc, pDst , Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_EnCryptBlockFWD(&(pContext->S), ldmc_IN_PLACE( pDst), Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_DualDeCryptBlockDIB(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;

  if( (ErrorCode = ldmc_DeCryptBlockFWD(&(pContext->S),          pSrc, pDst , Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_DeCryptBlockBWD(&(pContext->P), ldmc_IN_PLACE( pDst), Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_DualReSetContextsForNewBlockChainAndCall(ldmc_pDualBlockProcessor pBlockProcessor, ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pBlockProcessor ) return ldmc_ErrorCode_BlockProcessorIsNULL;

  if( !pSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pDst ) return ldmc_ErrorCode_DstIsNULL;

  if( (ErrorCode = ldmc_DualReSetContextsForNewBlockChain(pContext                  )) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode =                     (*pBlockProcessor)(pContext, pSrc, pDst, Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_DualCallAndReSetContextsForNewBlockChain(ldmc_pDualBlockProcessor pBlockProcessor, ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pBlockProcessor ) return ldmc_ErrorCode_BlockProcessorIsNULL;

  if( !pSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pDst ) return ldmc_ErrorCode_DstIsNULL;

  if( (ErrorCode =                     (*pBlockProcessor)(pContext, pSrc, pDst, Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_DualReSetContextsForNewBlockChain(pContext                  )) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



