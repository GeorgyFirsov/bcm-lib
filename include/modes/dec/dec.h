/**
 * @file dec.h
 * @brief DEC mode of operation header
 */

#ifndef BCMLIB_DEC_INCLUDED
#define BCMLIB_DEC_INCLUDED

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
 * @brief Encrypts a sector in DEC mode of operation.
 *
 * @param partition 
 * @param sector number of sector to encrypt
 * @param in data of the sector
 * @param blocks number of blocks in the sector
 * @param data_key key used to encrypt data
 * @param tweak_key key used to derive a tweak
 * @param out ciphertext
 * @param cipher cipher interface to use
 */
void dec_encrypt(unsigned long long partition, unsigned long long partition_counter,
                 unsigned long long sector, unsigned long long sector_counter,
                 const unsigned char* in, unsigned long blocks, const unsigned char* master_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Performs actual encryption in DEC mode. 
 *        This function exists for testing purposes. 
 */
void dec_encrypt_perform(unsigned long long partition, unsigned long long partition_counter,
                         unsigned long long sector, unsigned long long sector_counter,
                         const unsigned char* in, unsigned long blocks, const KEY* master_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Decrypts a sector in DEC mode of operation.
 * 
 * @param partition 
 * @param sector number of sector to decrypt
 * @param in encrypted data of the sector
 * @param blocks number of blocks in the sector
 * @param data_key key used to decrypt data
 * @param tweak_key key used to derive a tweak
 * @param out plaintext
 * @param cipher cipher interface to use
 */
void dec_decrypt(unsigned long long partition, unsigned long long partition_counter,
                 unsigned long long sector, unsigned long long sector_counter,
                 const unsigned char* in, unsigned long blocks, const unsigned char* master_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher);


/**
 * @brief Performs actual decryption in DEC mode. 
 *        This function exists for testing purposes. 
 */
void dec_decrypt_perform(unsigned long long partition, unsigned long long partition_counter,
                         unsigned long long sector, unsigned long long sector_counter,
                         const unsigned char* in, unsigned long blocks, const KEY* master_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher);


#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // !BCMLIB_DEC_INCLUDED