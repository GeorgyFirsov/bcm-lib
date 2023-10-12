/**
 * @file heh.c
 * @brief HEH mode of operation implementation
 */

#include "modes/heh/heh.h"
#include "common/utils.h"
#include "bclib.h"
#include "galoislib.h"

#include <immintrin.h>


/**
 * @brief Initialize HEH tweaks.
 */
BCMLIB_FORCEINLINE void hehp_tweaks_init(unsigned long long tweak, const KEY* key,
                                         __m128i* tau, __m128i* beta,
                                         const BLOCK_CIPHER* cipher)
{
    __m128i internal_tweak;
    unsigned int idx;
    BCMLIB_ALIGN16 unsigned char internal_tweak_bytes[MAX_BLOCK_SIZE];

    for (idx = 0; idx < sizeof(internal_tweak_bytes); ++idx)
    {
        internal_tweak_bytes[idx] = (unsigned char)(tweak & 0xFF);
        tweak >>= 8;
    }

    internal_tweak = _mm_load_si128((const __m128i*)internal_tweak_bytes);

    cipher->encrypt_block(internal_tweak, key, tau);
    *beta = gf128_multiply_primitive(*tau);
}


/**
 * @brief Apply psi permutation.
 */
BCMLIB_FORCEINLINE void hehp_apply_psi(const __m128i* in, unsigned long blocks,
                                       __m128i tau, __m128i beta, __m128i* out)
{
    //
    // Implementation of psi permutation:
    // psi(x[1], ..., x[n]) = (x[1] + Y, ..., x[n-1] + Y, Y) + e
    //
    // Y = x[n] + x[n - 1] * tau + ... + x[1] * tau ^ {n - 1}
    // e = (a * beta, ..., a ^ {n - 1} * tweak, tweak)
    //

    __m128i Y;
    __m128i accumulated_tweak;
    unsigned int block;

    //
    // Calculate Y value of psi
    //

    Y = _mm_setzero_si128();

    for (block = 0; block < blocks - 1; ++block)
    {
        Y = _mm_xor_si128(Y, in[block]);
        Y = gf128_multiply(Y, tau);
    }

    //
    // Finally add the last block
    //

    Y = _mm_xor_si128(Y, in[blocks - 1]);

    //
    // Apply psi transformation
    //

    accumulated_tweak = gf128_multiply_primitive(beta);

    for (block = 0; block < blocks - 1; ++block)
    {
        out[block]        = _mm_xor_si128(in[block], Y);
        out[block]        = _mm_xor_si128(out[block], accumulated_tweak);
        accumulated_tweak = gf128_multiply_primitive(accumulated_tweak);
    }

    out[blocks - 1] = _mm_xor_si128(Y, beta);
}


/**
 * @brief Apply inverse of psi permutation.
 */
BCMLIB_FORCEINLINE void hehp_apply_psi_inverse(const __m128i* in, unsigned long blocks,
                                               __m128i tau, __m128i beta, __m128i* out)
{
    //
    // Implementation of inverse of psi
    //

    __m128i Y;
    __m128i accumulated_tweak;
    __m128i temp;
    unsigned int block;

    //
    // Firstly remove mask
    //

    accumulated_tweak = gf128_multiply_primitive(beta);

    for (block = 0; block < blocks - 1; ++block)
    {
        out[block]        = _mm_xor_si128(in[block], accumulated_tweak);
        accumulated_tweak = gf128_multiply_primitive(accumulated_tweak);
    }

    out[blocks - 1] = _mm_xor_si128(in[blocks - 1], beta);

    //
    // Now recover n - 1 blocks
    //

    temp = out[blocks - 1];

    for (block = 0; block < blocks - 1; ++block)
    {
        out[block] = _mm_xor_si128(out[block], temp);
    }

    //
    // Now recover the last one
    //

    Y = _mm_setzero_si128();

    for (block = 0; block < blocks - 1; ++block)
    {
        Y = _mm_xor_si128(Y, out[block]);
        Y = gf128_multiply(Y, tau);
    }

    //
    // Finally add the pre-last block and recover the last one
    //

    out[blocks - 1] = _mm_xor_si128(out[blocks - 1], Y);
}


void heh_encrypt(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                 const unsigned char* key, unsigned char* out, const BLOCK_CIPHER* cipher)
{
    KEY internal_key;
    cipher->initialize_encrypt_key(key, &internal_key);

    heh_encrypt_perform(tweak, in, blocks, &internal_key, out, cipher);
}


void heh_encrypt_perform(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                         const KEY* key, unsigned char* out, const BLOCK_CIPHER* cipher)
{
    unsigned int block;

    __m128i tau;
    __m128i beta;

    const __m128i* internal_in = (const __m128i*)in;
    __m128i* internal_out      = (__m128i*)out;

    hehp_tweaks_init(tweak, key, &tau, &beta, cipher);

    //
    // First hash stage
    //

    hehp_apply_psi(internal_in, blocks, tau, beta, internal_out);

    //
    // ECB encryption
    //

    for (block = 0; block < blocks; ++block)
    {
        cipher->encrypt_block(internal_out[block], key, &internal_out[block]);
    }

    //
    // Second hash stage
    //

    hehp_apply_psi_inverse(internal_out, blocks, tau, beta, internal_out);
}


void heh_decrypt(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                 const unsigned char* key, unsigned char* out, const BLOCK_CIPHER* cipher)
{
    KEY internal_data_key;
    KEY internal_tweak_key;

    cipher->initialize_decrypt_key(key, &internal_data_key);
    cipher->initialize_encrypt_key(key, &internal_tweak_key);

    heh_decrypt_perform(tweak, in, blocks, &internal_data_key,
                        &internal_tweak_key, out, cipher);
}


void heh_decrypt_perform(unsigned long long tweak, const unsigned char* in, unsigned long blocks,
                         const KEY* data_key, const KEY* tweak_key, unsigned char* out, const BLOCK_CIPHER* cipher)
{
    unsigned int block;

    __m128i tau;
    __m128i beta;

    const __m128i* internal_in = (const __m128i*)in;
    __m128i* internal_out      = (__m128i*)out;

    hehp_tweaks_init(tweak, tweak_key, &tau, &beta, cipher);

    //
    // First hash stage
    //

    hehp_apply_psi(internal_in, blocks, tau, beta, internal_out);

    //
    // ECB decryption
    //

    for (block = 0; block < blocks; ++block)
    {
        cipher->decrypt_block(internal_out[block], data_key, &internal_out[block]);
    }

    //
    // Second hash stage
    //

    hehp_apply_psi_inverse(internal_out, blocks, tau, beta, internal_out);
}
