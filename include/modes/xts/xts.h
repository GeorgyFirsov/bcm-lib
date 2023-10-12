/**
 * @file xts.h
 * @brief XTS mode of operation header
 */

#ifndef BCMLIB_XTS_INCLUDED
#define BCMLIB_XTS_INCLUDED

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
 * @brief Encrypts a sector in XTS mode of operation.
 *
 * @param sector number of sector to encrypt
 * @param in data of the sector
 * @param blocks number of blocks in the sector
 * @param data_key key used to encrypt data
 * @param tweak_key key used to derive a tweak
 * @param out ciphertext
 * @param cipher cipher interface to use
 */
void xts_encrypt(unsigned long long sector, const unsigned char* in, unsigned long blocks,
                 const unsigned char* data_key, const unsigned char* tweak_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Performs actual encryption in XTS mode. 
 *        This function exists for testing purposes. 
 */
void xts_encrypt_perform(unsigned long long sector, const unsigned char* in, unsigned long blocks,
                         const KEY* data_key, const KEY* tweak_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Decrypts a sector in XTS mode of operation.
 * 
 * @param sector number of sector to decrypt
 * @param in encrypted data of the sector
 * @param blocks number of blocks in the sector
 * @param data_key key used to decrypt data
 * @param tweak_key key used to derive a tweak
 * @param out plaintext
 * @param cipher cipher interface to use
 */
void xts_decrypt(unsigned long long sector, const unsigned char* in, unsigned long blocks,
                 const unsigned char* data_key, const unsigned char* tweak_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Performs actual decryption in XTS mode. 
 *        This function exists for testing purposes. 
 */
void xts_decrypt_perform(unsigned long long sector, const unsigned char* in, unsigned long blocks,
                         const KEY* data_key, const KEY* tweak_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // !BCMLIB_XTS_INCLUDED