#ifndef __LDOMBIMICROCIPHER2017_H
#define __LDOMBIMICROCIPHER2017_H



#include "LDombiMicroCipher2017_Config.h"



#define ldmc_KEY_LEN_MAX ldmc_KEY_BUF_LEN
#define ldmc_KEY_LEN_MIN 2

#define ldmc_DEPTH_MAX ldmc_DIAL_BUF_LEN
#define ldmc_DEPTH_MIN 1

#define ldmc_NOISE_MAX ldmc_MASK_SET_BUF_LEN_LOG2
#define ldmc_NOISE_MIN 0



#if (ldmc_KEY_BUF_LEN < ldmc_KEY_LEN_MIN)
#error Wrong Config: ldmc_KEY_BUF_LEN < ldmc_KEY_LEN_MIN
#endif

#if (ldmc_DIAL_BUF_LEN < ldmc_DEPTH_MIN)
#error Wrong Config: ldmc_DIAL_BUF_LEN < ldmc_DEPTH_MIN
#endif

#if (ldmc_DEPTH_DEF < ldmc_DEPTH_MIN)
#error Wrong Config: ldmc_DEPTH_DEF < ldmc_DEPTH_MIN
#endif

#if (ldmc_DEPTH_DEF > ldmc_DEPTH_MAX)
#error Wrong Config: ldmc_DEPTH_DEF > ldmc_DEPTH_MAX
#endif

#if (ldmc_MASK_SET_BUF_LEN_LOG2 > 8)
#error Wrong Config: ldmc_MASK_SET_BUF_LEN_LOG2 > 8
#endif

#if (ldmc_NOISE_DEF < ldmc_NOISE_MIN)
#error Wrong Config: ldmc_NOISE_DEF < ldmc_NOISE_MIN
#endif

#if (ldmc_NOISE_DEF > ldmc_NOISE_MAX)
#error Wrong Config: ldmc_NOISE_DEF > ldmc_NOISE_MAX
#endif



#define ldmc_IN_PLACE( pBuf ) pBuf, pBuf

#define ldmc_DEFAULT_ARGUMENTS_Depth_Noise_Seed ldmc_DEPTH_DEF, ldmc_NOISE_DEF, ldmc_SEED_DEF
#define ldmc_DEFAULT_ARGUMENTS_Noise_Seed                       ldmc_NOISE_DEF, ldmc_SEED_DEF
#define ldmc_DEFAULT_ARGUMENTS_Seed                                             ldmc_SEED_DEF



typedef ldmc_EXTERNAL_TYPE_tByte ldmc_tByte, *ldmc_pByte;
typedef ldmc_EXTERNAL_TYPE_tDial ldmc_tDial, *ldmc_pDial;
typedef ldmc_EXTERNAL_TYPE_tSeed ldmc_tSeed, *ldmc_pSeed;



typedef struct ldmc_sMaskSet
{

  ldmc_tByte Mask0;
  ldmc_tByte Mask1;
  ldmc_tByte Mask2;
  ldmc_tByte Mask3;

} ldmc_tMaskSet, *ldmc_pMaskSet;



typedef struct ldmc_sCipherContext ldmc_tCipherContext, *ldmc_pCipherContext;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
typedef ldmc_tByte ldmc_tByteProcessor(ldmc_pCipherContext pContext, ldmc_tByte Input);
typedef ldmc_tByteProcessor *ldmc_pByteProcessor;
#endif



struct ldmc_sCipherContext
{

  ldmc_tByte Key[ldmc_KEY_BUF_LEN];
  ldmc_tDial Dials[ldmc_DIAL_BUF_LEN];
  unsigned int KeyLen;
  unsigned int Depth;
  ldmc_tSeed Seed;
  ldmc_tByte IMask;
  ldmc_tByte Index;
  ldmc_tByte LinkP;
  ldmc_tByte LinkC;
  ldmc_tMaskSet BackUpSet, MaskSets[((unsigned int)1) << ldmc_MASK_SET_BUF_LEN_LOG2];
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pEnCryptByte, pDeCryptByte;
#endif

};



typedef struct ldmc_sDualCipherContext
{

  ldmc_tCipherContext P;
  ldmc_tCipherContext S;

} ldmc_tDualCipherContext, *ldmc_pDualCipherContext;



typedef enum ldmc_eErrorCode
{

  ldmc_ErrorCode_NoError            = 0,
  ldmc_ErrorCode_ldmc_tByte_SizeNot1   ,
  ldmc_ErrorCode_ldmc_tDial_TooShort   ,
  ldmc_ErrorCode_BlockProcessorIsNULL  ,
  ldmc_ErrorCode_ContextIsNULL         ,
  ldmc_ErrorCode_KeyBufIsNULL          ,
  ldmc_ErrorCode_WrongKeyLen           ,
  ldmc_ErrorCode_WrongDepth            ,
  ldmc_ErrorCode_WrongNoise            ,
  ldmc_ErrorCode_SrcIsNULL             ,
  ldmc_ErrorCode_DstIsNULL             

} ldmc_tErrorCode, *ldmc_pErrorCode;



typedef ldmc_tErrorCode ldmc_tBlockProcessor(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
typedef ldmc_tBlockProcessor *ldmc_pBlockProcessor;

typedef ldmc_tErrorCode ldmc_tDualBlockProcessor(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
typedef ldmc_tDualBlockProcessor *ldmc_pDualBlockProcessor;



ldmc_tErrorCode ldmc_InitCipherContext(ldmc_pCipherContext pContext, ldmc_tByte KeyBuf[], unsigned int KeyLen, unsigned int Depth, unsigned int Noise, ldmc_tSeed Seed);

ldmc_tErrorCode ldmc_ReSetContextForNewBlockChain(ldmc_pCipherContext pContext);

ldmc_tErrorCode ldmc_EnCryptBlockFWD(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_DeCryptBlockFWD(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);

ldmc_tErrorCode ldmc_EnCryptBlockBWD(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_DeCryptBlockBWD(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);

ldmc_tErrorCode ldmc_ReSetContextForNewBlockChainAndCall(ldmc_pBlockProcessor pBlockProcessor, ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_CallAndReSetContextForNewBlockChain(ldmc_pBlockProcessor pBlockProcessor, ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);



ldmc_tErrorCode ldmc_DualInitCipherContexts(ldmc_pDualCipherContext pContext, ldmc_tByte KeyBuf[], unsigned int KeyLen, unsigned int Depth, unsigned int Noise, ldmc_tSeed Seed);
ldmc_tErrorCode ldmc_DualDetailedInitCipherContexts(ldmc_pDualCipherContext pContext, ldmc_tByte KeyBufP[], unsigned int KeyLenP, unsigned int DepthP, unsigned int NoiseP, ldmc_tSeed SeedP, ldmc_tByte KeyBufS[], unsigned int KeyLenS, unsigned int DepthS, unsigned int NoiseS, ldmc_tSeed SeedS);

ldmc_tErrorCode ldmc_DualReSetContextsForNewBlockChain(ldmc_pDualCipherContext pContext);

ldmc_tErrorCode ldmc_DualEnCryptBlockFWD(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_DualDeCryptBlockFWD(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);

ldmc_tErrorCode ldmc_DualEnCryptBlockBWD(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_DualDeCryptBlockBWD(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);

ldmc_tErrorCode ldmc_DualEnCryptBlockBID(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_DualDeCryptBlockBID(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);

ldmc_tErrorCode ldmc_DualEnCryptBlockDIB(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_DualDeCryptBlockDIB(ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);

ldmc_tErrorCode ldmc_DualReSetContextsForNewBlockChainAndCall(ldmc_pDualBlockProcessor pBlockProcessor, ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_CallAndDualReSetContextsForNewBlockChain(ldmc_pDualBlockProcessor pBlockProcessor, ldmc_pDualCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);



#endif /* __LDOMBIMICROCIPHER2017_H */
