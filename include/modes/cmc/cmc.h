/**
 * @file cmc.h
 * @brief CMC mode of operation header
 */

#ifndef BCMLIB_CMC_INCLUDED
#define BCMLIB_CMC_INCLUDED

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
 * @brief Encrypts a sector in CMC mode of operation.
 *
 * @param tweak tweak used for encryption
 * @param in data of the sector
 * @param blocks number of blocks in the sector
 * @param data_key key used to encrypt data
 * @param tweak_key key used to encrypt tweak
 * @param out ciphertext
 * @param cipher cipher interface to use
 */
void cmc_encrypt(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                 const unsigned char* data_key, const unsigned char* tweak_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Performs actual encryption in CMC mode. 
 *        This function exists for testing purposes. 
 */
void cmc_encrypt_perform(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                         const KEY* data_key, const KEY* tweak_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Decrypts a sector in CMC mode of operation.
 *
 * @param tweak tweak used for decryption
 * @param in encrypted data of the sector
 * @param blocks number of blocks in the sector
 * @param data_key key used to decrypt data
 * @param tweak_key key used to encrypt tweak
 * @param out plaintext
 * @param cipher cipher interface to use
 */
void cmc_decrypt(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                 const unsigned char* data_key, const unsigned char* tweak_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Performs actual decryption in CMC mode. 
 *        This function exists for testing purposes. 
 */
void cmc_decrypt_perform(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                         const KEY* data_key, const KEY* tweak_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher);


#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // !BCMLIB_CMC_INCLUDED