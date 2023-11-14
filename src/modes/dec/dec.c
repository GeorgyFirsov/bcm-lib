/**
 * @file dec.c
 * @brief DEC mode of operation implementation
 */

#include "modes/dec/dec.h"
#include "modes/cmac/cmac.h"
#include "common/utils.h"
#include "bclib.h"
#include "kdflib.h"

#include <immintrin.h>


/**
 * @brief Internal context, that is used in KDF functions.
 */
typedef struct tagDECP_KDF_CONTEXT
{
    const BLOCK_CIPHER* cipher; /**< Block cipher instance for CMAC */

    unsigned long tag_size; /**< CMAC tag size in bits */

    unsigned long format_blocks; /**< Number of blocks in `decp_kdf_format` output */
} DECP_KDF_CONTEXT;


/**
 * @brief Initializes master key for DEC mode.
 */
BCMLIB_FORCEINLINE void decp_initialize_key(const unsigned char* key, KEY* out, const BLOCK_CIPHER* cipher)
{
    cipher->initialize_encrypt_key(key, out);
}


/**
 * @brief Calculates DEC's v parameter.
 */
BCMLIB_FORCEINLINE unsigned long long decp_calculate_v(unsigned long blocks, unsigned long block_size)
{
    //
    // I need block size in bits and all values to of the same type
    //

    unsigned long long internal_block_size = block_size << 3;
    unsigned long long internal_blocks     = blocks;

    //
    // Some magic here
    //

    return (((unsigned long long)1 << ((internal_block_size >> 1) - 1)) / internal_blocks) << 1;
}


/**
 * @brief Implementation of key initialization function for KDF.
 */
BCMLIB_FORCEINLINE void decp_kdf_initialize_key(const unsigned char* key, void* user_context, unsigned char* out)
{
    KEY* internal_out               = (KEY*)out;
    const DECP_KDF_CONTEXT* context = (const DECP_KDF_CONTEXT*)user_context;

    decp_initialize_key(key, internal_out, context->cipher);
}


/**
 * @brief Implementation of format function for KDF.
 */
BCMLIB_FORCEINLINE void decp_kdf_format(const unsigned char* z, unsigned long c, const unsigned char* p,
                                        const unsigned char* u, const unsigned char* a, const unsigned char* l,
                                        void* user_context, unsigned char* out)
{
    BCMLIB_UNUSED(c);
    BCMLIB_UNUSED(u);
    BCMLIB_UNUSED(a);
    BCMLIB_UNUSED(l);
    BCMLIB_UNUSED(user_context);

    const __m128i* internal_z = (const __m128i*)z;
    const __m128i* internal_p = (const __m128i*)p;
    __m128i* internal_out     = (__m128i*)out;

    internal_out[0] = *internal_z;
    internal_out[1] = *internal_p;
}


/**
 * @brief Implementation of MAC function for KDF.
 */
BCLIB_FORCEINLINE void decp_kdf_mac(const unsigned char* key, const unsigned char* in, void* user_context, unsigned char* out)
{
    const KEY* internal_key         = (const KEY*)key;
    const DECP_KDF_CONTEXT* context = (const DECP_KDF_CONTEXT*)user_context;

    cmac_digest_perform(in, context->format_blocks, internal_key, context->tag_size, out, context->cipher);
}


void dec_encrypt(unsigned long long partition, unsigned long long partition_counter,
                 unsigned long long sector, unsigned long long sector_counter,
                 const unsigned char* in, unsigned long blocks, const unsigned char* master_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher)
{
    KEY internal_master_key;
    decp_initialize_key(master_key, &internal_master_key, cipher);

    dec_encrypt_perform(partition, partition_counter, sector, sector_counter,
                        in, blocks, &internal_master_key, out, cipher);
}


void dec_encrypt_perform(unsigned long long partition, unsigned long long partition_counter,
                         unsigned long long sector, unsigned long long sector_counter,
                         const unsigned char* in, unsigned long blocks, const KEY* master_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher)
{
    unsigned long long counter_base = sector_counter * blocks;
    unsigned long long normalized_sector_counter;
    unsigned long block;

    KEY partition_key_buffer;
    KEY partition_key;

    KEY sector_key_buffer;
    KEY sector_key;

    __m128i counter;
    __m128i kdf_iv;
    __m128i kdf_p;
    __m128i kdf_format_buffer[2];

    const __m128i* internal_in = (const __m128i*)in;
    __m128i* internal_out      = (__m128i*)out;

    DECP_KDF_CONTEXT kdf_user_context = {
        .cipher        = cipher,
        .tag_size      = BCMLIB_CMAC_TAG_SIZE_128,
        .format_blocks = BCMLIB_COUNTOF(kdf_format_buffer)
    };

    R1323665_1_022_2018_KDF2_CONTEXT kdf_context = {
        .key_buffer     = (unsigned char*)master_key,
        .format_buffer  = (unsigned char*)kdf_format_buffer,
        .mac_size       = kdf_user_context.tag_size >> 3,
        .user_context   = &kdf_user_context,
        .initialize_key = decp_kdf_initialize_key,
        .format         = decp_kdf_format,
        .mac            = decp_kdf_mac
    };

    //
    // Derive partition key via:
    //   IV  = 0
    //   P   = partition || partition_counter
    //   K_p = kdf2(master_key, IV, P)
    //
    // Since master key is already initialized here,
    // I can use faster `kdf2_perform` function
    //

    kdf_iv = _mm_setzero_si128();
    kdf_p  = _mm_set_epi64x((long long)partition, (long long)partition_counter);

    kdf2_perform((const unsigned char*)&kdf_iv, NULL, (const unsigned char*)&kdf_p, NULL, NULL,
                 cipher->key_size, &kdf_context, partition_key_buffer.key);

    //
    // Derive sector key via:
    //   IV  = partition || 0
    //   P   = (sector_counter / v) || sector
    //   K_s = kdf2(K_p, IV, P)
    //

    normalized_sector_counter = sector_counter / decp_calculate_v(blocks, cipher->block_size);
    kdf_iv                    = _mm_set_epi64x((long long)partition, 0);
    kdf_p                     = _mm_set_epi64x((long long)normalized_sector_counter, (long long)sector);

    kdf_context.key_buffer = (unsigned char*)&partition_key;

    kdf2(partition_key_buffer.key, (const unsigned char*)&kdf_iv, NULL,
         (const unsigned char*)&kdf_p, NULL, NULL, cipher->key_size,
         &kdf_context, sector_key_buffer.key);

    //
    // Let's perform encryption
    // Gamma is generated via:
    //   ctr(t)  = sector || (sector_counter * blocks + t)
    //   gamma_t = Enc(K_s, ctr(t))
    //

    cipher->initialize_encrypt_key(sector_key_buffer.key, &sector_key);

    for (block = 0; block < blocks; ++block)
    {
        counter = _mm_set_epi64x((long long)sector, (long long)(counter_base + block));

        cipher->encrypt_block(counter, &sector_key, &internal_out[block]);
        internal_out[block] = _mm_xor_si128(internal_in[block], internal_out[block]);
    }
}


void dec_decrypt(unsigned long long partition, unsigned long long partition_counter,
                 unsigned long long sector, unsigned long long sector_counter,
                 const unsigned char* in, unsigned long blocks, const unsigned char* master_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher)
{
    KEY internal_master_key;
    decp_initialize_key(master_key, &internal_master_key, cipher);

    dec_decrypt_perform(partition, partition_counter, sector, sector_counter,
                        in, blocks, &internal_master_key, out, cipher);
}


void dec_decrypt_perform(unsigned long long partition, unsigned long long partition_counter,
                         unsigned long long sector, unsigned long long sector_counter,
                         const unsigned char* in, unsigned long blocks, const KEY* master_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher)
{
    dec_encrypt_perform(partition, partition_counter, sector, sector_counter,
                        in, blocks, master_key, out, cipher);
}
