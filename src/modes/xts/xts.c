/**
 * @file xts.c
 * @brief XTS mode of operation implementation
 */

#include "modes/xts/xts.h"
#include "common/utils.h"
#include "bclib.h"
#include "galoislib.h"

#include <immintrin.h>


/**
 * @brief Initialize XTS tweak.
 */
BCMLIB_FORCEINLINE __m128i xtsp_tweak_init(unsigned long long sector, const KEY* tweak_key, const BLOCK_CIPHER* cipher)
{
    __m128i tweak;
    unsigned int idx;
    BCMLIB_ALIGN16 unsigned char internal_tweak[MAX_BLOCK_SIZE];

    for (idx = 0; idx < sizeof(internal_tweak); ++idx)
    {
        internal_tweak[idx] = (unsigned char)(sector & 0xFF);
        sector >>= 8;
    }

    tweak = _mm_load_si128((const __m128i*)internal_tweak);
    cipher->encrypt_block(tweak, tweak_key, &tweak);

    return tweak;
}


void xts_encrypt(unsigned long long sector, const unsigned char* in, unsigned long blocks,
                 const unsigned char* data_key, const unsigned char* tweak_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher)
{
    KEY internal_data_key;
    KEY internal_tweak_key;

    cipher->initialize_encrypt_key(data_key, &internal_data_key);
    cipher->initialize_encrypt_key(tweak_key, &internal_tweak_key);

    xts_encrypt_perform(sector, in, blocks, &internal_data_key,
                        &internal_tweak_key, out, cipher);
}


void xts_encrypt_perform(unsigned long long sector, const unsigned char* in, unsigned long blocks,
                         const KEY* data_key, const KEY* tweak_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher)
{
    unsigned int block;

    __m128i temporary;
    __m128i tweak;

    tweak = xtsp_tweak_init(sector, tweak_key, cipher);

    for (block = 0; block < blocks; ++block, in += cipher->block_size, out += cipher->block_size)
    {
        //
        // Encrypt block
        //

        temporary = _mm_loadu_si128((const __m128i*)in);

        temporary = _mm_xor_si128(temporary, tweak);
        cipher->encrypt_block(temporary, data_key, &temporary);
        temporary = _mm_xor_si128(temporary, tweak);

        _mm_storeu_si128((__m128i*)out, temporary);

        //
        // Multiply tweak by x (alpha)
        //

        tweak = gf128_multiply_primitive(tweak);
    }
}


void xts_decrypt(unsigned long long sector, const unsigned char* in, unsigned long blocks,
                 const unsigned char* data_key, const unsigned char* tweak_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher)
{
    KEY internal_data_key;
    KEY internal_tweak_key;

    cipher->initialize_decrypt_key(data_key, &internal_data_key);
    cipher->initialize_encrypt_key(tweak_key, &internal_tweak_key);

    xts_decrypt_perform(sector, in, blocks, &internal_data_key,
                        &internal_tweak_key, out, cipher);
}


void xts_decrypt_perform(unsigned long long sector, const unsigned char* in, unsigned long blocks,
                         const KEY* data_key, const KEY* tweak_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher)
{
    unsigned int block;

    __m128i temporary;
    __m128i tweak;

    tweak = xtsp_tweak_init(sector, tweak_key, cipher);

    for (block = 0; block < blocks; ++block, in += cipher->block_size, out += cipher->block_size)
    {
        //
        // Encrypt block
        //

        temporary = _mm_loadu_si128((const __m128i*)in);

        temporary = _mm_xor_si128(temporary, tweak);
        cipher->decrypt_block(temporary, data_key, &temporary);
        temporary = _mm_xor_si128(temporary, tweak);

        _mm_storeu_si128((__m128i*)out, temporary);

        //
        // Multiply tweak by x (alpha)
        //

        tweak = gf128_multiply_primitive(tweak);
    }
}
