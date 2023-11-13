/**
 * @file cmac.h
 * @brief CMAC mode of operation header
 */

#ifndef BCMLIB_CMAC_INCLUDED
#define BCMLIB_CMAC_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus


/**
 * @brief Forward-declaration of block cipher interface (see bc-lib)
 */
typedef struct tagBLOCK_CIPHER BLOCK_CIPHER;


/**
 * @brief Forward-declaration of key structure (see bc-lib)
 */
typedef struct tagKEY KEY;


/**
 * @brief Possible values of `significant_bits` parameter.
 */
#define BCMLIB_CMAC_TAG_SIZE_64     (64)
#define BCMLIB_CMAC_TAG_SIZE_128    (128)


/**
 * @brief Enumeration, that contains a set of possible
 *        MAC verification results
 */
typedef enum tag_cmac_verify_result
{
    cmac_valid,   /**< Denotes successful CMAC tag verification */
    cmac_invalid, /**< Denotes CMAC tag verification failure */
} cmac_verify_result;


/**
 * @brief Computes CMAC using 128-bit block cipher.
 *        Tag is `significan_bits` bit long and is stored in most significant
 *        bits of 128-bit output value.
 * 
 * @param in set of several full 128-bit blocks to compute MAC for
 * @param blocks number of blocks in data
 * @param key MAC key
 * @param significan_bits number of bits in MAC, other bits will be zeroed.
 *                        Possible values: see `BCMLIB_CMAC_TAG_SIZE_*` constants
 * @param out pointer to a 128-bit value, that receives the value of MAC 
 * @param cipher cipher interface to use
 */
void cmac_digest(const unsigned char* in, unsigned long blocks,
                 const unsigned char* key, unsigned long significant_bits,
                 unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Performs actual CMAC digest calculation. 
 *        This function exists for testing purposes. 
 */
void cmac_digest_perform(const unsigned char* in, unsigned long blocks,
                         const KEY* key, unsigned long significant_bits,
                         unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Verifies MAC computed using 'cmacaes_digest'.
 *        `significan_bits`-bit MAC is the only supported.
 *
 * @param in set of several full 128-bit blocks to verify MAC for
 * @param blocks number of blocks in data
 * @param key MAC key
 * @param tag pointer to a 128-bit value, that contains the value of MAC
 * @param significan_bits number of bits in MAC, other bits will be zeroed.
 *                        Possible values: see `BCMLIB_CMAC_TAG_SIZE_*` constants
 * @param cipher cipher interface to use
 * 
 * @return 'cmac_valid' if MAC is correct and 'cmac_invalid' -- otherwise
 */
cmac_verify_result cmac_verify(const unsigned char* in, unsigned long blocks,
                               const unsigned char* key, const unsigned char* tag,
                               unsigned long significant_bits, const BLOCK_CIPHER* cipher);


/**
 * @brief Performs actual CMAC digest verification. 
 *        This function exists for testing purposes. 
 */
cmac_verify_result cmac_verify_perform(const unsigned char* in, unsigned long blocks,
                                       const KEY* key, const unsigned char* tag,
                                       unsigned long significant_bits, const BLOCK_CIPHER* cipher);


#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // !BCMLIB_CMAC_INCLUDED