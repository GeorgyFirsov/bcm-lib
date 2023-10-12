/**
 * @file cmc.c
 * @brief CMC mode of operation implementation
 */

#include "modes/cmc/cmc.h"
#include "common/utils.h"
#include "bclib.h"
#include "galoislib.h"

#include <immintrin.h>


#define LO32(n) ((n)&0xFFFFFFFF)
#define HI32(n) ((n) >> 32)


void cmc_encrypt(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                 const unsigned char* data_key, const unsigned char* tweak_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher)
{
    KEY internal_data_key;
    KEY internal_tweak_key;

    cipher->initialize_encrypt_key(data_key, &internal_data_key);
    cipher->initialize_encrypt_key(tweak_key, &internal_tweak_key);

    cmc_encrypt_perform(tweak, in, blocks, &internal_data_key,
                        &internal_tweak_key, out, cipher);
}


void cmc_encrypt_perform(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                         const KEY* data_key, const KEY* tweak_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher)
{
    unsigned int block;

    __m128i temporary1;
    __m128i temporary2;
    __m128i encrypted_tweak;

    const __m128i* internal_in = (const __m128i*)in;
    __m128i* internal_out      = (__m128i*)out;

    __m128i internal_tweak = _mm_setr_epi32(LO32(tweak), HI32(tweak), 0x00, 0x00);
    __m128i two            = _mm_setr_epi32(0x02, 0x00, 0x00, 0x00);

    //
    // Encrypt tweak
    //

    cipher->encrypt_block(internal_tweak, tweak_key, &encrypted_tweak);

    //
    // First CBC-encryption pass
    //

    temporary1 = encrypted_tweak;

    for (block = 0; block < blocks; ++block)
    {
        temporary1 = _mm_xor_si128(temporary1, internal_in[block]);
        cipher->encrypt_block(temporary1, data_key, &temporary1);

        internal_out[block] = temporary1;
    }

    //
    // Masking
    //

    temporary1 = _mm_xor_si128(internal_out[0], internal_out[blocks - 1]);
    temporary1 = gf128_multiply(temporary1, two);

    for (block = 0; block < blocks; ++block)
    {
        internal_out[block] = _mm_xor_si128(internal_out[block], temporary1);
    }

    //
    // Second CBC-encryption pass
    //

    temporary1 = _mm_setzero_si128();

    for (block = 0; block < blocks; ++block)
    {
        temporary2 = internal_out[blocks - block - 1];

        cipher->encrypt_block(internal_out[blocks - block - 1], data_key, &internal_out[blocks - block - 1]);

        internal_out[blocks - block - 1] = _mm_xor_si128(temporary1, internal_out[blocks - block - 1]);
        temporary1                       = temporary2;
    }

    internal_out[blocks - 1] = _mm_xor_si128(encrypted_tweak, internal_out[blocks - 1]);
}


void cmc_decrypt(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                 const unsigned char* data_key, const unsigned char* tweak_key,
                 unsigned char* out, const BLOCK_CIPHER* cipher)
{
    KEY internal_data_key;
    KEY internal_tweak_key;

    cipher->initialize_decrypt_key(data_key, &internal_data_key);
    cipher->initialize_encrypt_key(tweak_key, &internal_tweak_key);

    cmc_decrypt_perform(tweak, in, blocks, &internal_data_key,
                        &internal_tweak_key, out, cipher);
}


void cmc_decrypt_perform(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                         const KEY* data_key, const KEY* tweak_key,
                         unsigned char* out, const BLOCK_CIPHER* cipher)
{
    unsigned int block;

    __m128i temporary1;
    __m128i temporary2;
    __m128i encrypted_tweak;

    const __m128i* internal_in = (const __m128i*)in;
    __m128i* internal_out      = (__m128i*)out;

    __m128i internal_tweak = _mm_setr_epi32(LO32(tweak), HI32(tweak), 0x00, 0x00);
    __m128i two            = _mm_setr_epi32(0x02, 0x00, 0x00, 0x00);

    //
    // Encrypt tweak
    //

    cipher->encrypt_block(internal_tweak, tweak_key, &encrypted_tweak);

    //
    // First CBC-decryption pass
    //

    temporary1 = encrypted_tweak;

    for (block = 0; block < blocks; ++block)
    {
        temporary1 = _mm_xor_si128(temporary1, internal_in[blocks - block - 1]);
        cipher->decrypt_block(temporary1, data_key, &temporary1);

        internal_out[block] = temporary1;
    }

    //
    // Masking
    //

    temporary1 = _mm_xor_si128(internal_out[0], internal_out[blocks - 1]);
    temporary1 = gf128_multiply(temporary1, two);

    for (block = 0; block < blocks; ++block)
    {
        internal_out[block] = _mm_xor_si128(internal_out[block], temporary1);
    }

    //
    // Second CBC-decryption pass
    //

    temporary1 = _mm_setzero_si128();

    for (block = 0; block < blocks; ++block)
    {
        temporary2 = internal_out[blocks - block - 1];

        cipher->decrypt_block(internal_out[blocks - block - 1], data_key, &internal_out[blocks - block - 1]);

        internal_out[blocks - block - 1] = _mm_xor_si128(temporary1, internal_out[blocks - block - 1]);
        temporary1                       = temporary2;
    }

    internal_out[blocks - 1] = _mm_xor_si128(encrypted_tweak, internal_out[blocks - 1]);
}
