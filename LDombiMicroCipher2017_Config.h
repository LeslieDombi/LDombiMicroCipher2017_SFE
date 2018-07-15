#ifndef __LDOMBIMICROCIPHER2017_CONFIG_H
#define __LDOMBIMICROCIPHER2017_CONFIG_H



#ifndef ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL
#define ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL 0
#endif /* Optimization for Speed, generates larger code. Values: 0, 1, 2, 3 */



#ifndef ldmc_EXTERNAL_TYPE_tByte
#define ldmc_EXTERNAL_TYPE_tByte unsigned char
#endif

#ifndef ldmc_EXTERNAL_TYPE_tDial
#define ldmc_EXTERNAL_TYPE_tDial unsigned short
#endif

#ifndef ldmc_EXTERNAL_TYPE_tSeed
#define ldmc_EXTERNAL_TYPE_tSeed unsigned int
#endif



#ifndef ldmc_KEY_BUF_LEN
#define ldmc_KEY_BUF_LEN 0x400
#endif /* Maximizes the KeyLen */

#ifndef ldmc_DIAL_BUF_LEN
#define ldmc_DIAL_BUF_LEN 0x200
#endif /* Maximizes the Depth */

#ifndef ldmc_MASK_SET_BUF_LEN_LOG2
#define ldmc_MASK_SET_BUF_LEN_LOG2 8
#endif  /* Maximizes the Noise. Values: 0 ... 8 */
/* ldmc_MASK_SET_BUF_LEN_LOG2-th power of 2 instances of Mask Sets are used */
/* Higher number does not affect performance but increases entropy */



#ifndef     ldmc_EnCryptBlock
#define     ldmc_EnCryptBlock ldmc_EnCryptBlockFWD
#endif

#ifndef     ldmc_DeCryptBlock
#define     ldmc_DeCryptBlock ldmc_DeCryptBlockFWD
#endif

#ifndef ldmc_DualEnCryptBlock
#define ldmc_DualEnCryptBlock ldmc_DualEnCryptBlockBID
#endif

#ifndef ldmc_DualDeCryptBlock
#define ldmc_DualDeCryptBlock ldmc_DualDeCryptBlockBID
#endif



#ifndef ldmc_DEPTH_DEF
#define ldmc_DEPTH_DEF 5
#endif

#ifndef ldmc_NOISE_DEF
#define ldmc_NOISE_DEF 3
#endif

#ifndef ldmc_SEED_DEF
#define ldmc_SEED_DEF 0
#endif



#endif /* __LDOMBIMICROCIPHER2017_CONFIG_H */
