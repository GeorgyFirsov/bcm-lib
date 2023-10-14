/**
 * @file cmac.c
 * @brief CMAC mode of operation implementation
 */

#include "modes/cmac/cmac.h"
#include "common/utils.h"
#include "bclib.h"

#include <immintrin.h>
#include <smmintrin.h>


/**
 * @brief Internal CMAC subkey
 */
typedef struct tagCMACP_SUBKEY
{
    __m128i key;
} CMACP_SUBKEY;


/**
 * @brief Mask that truncates a tag
 */
BCMLIB_FORCEINLINE __m128i cmacp_mask()
{
    //
    // 64 most significant bits
    //

    return _mm_setr_epi32(0xffffffff, 0xffffffff, 0x00, 0x00);
}


/**
 * @brief Performs left shift of argument by one bit
 * 
 * Well... Actually it does NOT perform a correct left shift by 1 bit,
 * but it seems, that all test vectors are created assuming this
 * implementation from RFC 4493 :(
 */
BCMLIB_FORCEINLINE __m128i cmacp_left_shift(__m128i in)
{
    signed int idx;
    unsigned char overflow = 0;
    __m128i result         = _mm_setzero_si128();

    unsigned char* internal_result = (unsigned char*)&result;
    unsigned char* internal_in     = (unsigned char*)&in;

    for (idx = 15; idx >= 0; --idx)
    {
        internal_result[idx] = internal_in[idx] << 1;
        internal_result[idx] |= overflow;
        overflow = (internal_in[idx] & 0x80) ? 1 : 0;
    }

    return result;
}


/**
 * @brief Creates CMAC subkeys
 */
BCMLIB_FORCEINLINE void cmacp_subkeys_init(const KEY* key, CMACP_SUBKEY* subkey1, CMACP_SUBKEY* subkey2,
                                           const BLOCK_CIPHER* cipher)
{
    //
    // GOST 34.13-2015
    //

    __m128i temporary;
    __m128i internal_subkey1;
    __m128i internal_subkey2;
    __m128i R;

    //
    // B128 = 0b00...0010000111 = 0x87
    //

    __m128i B128 = _mm_setr_epi32(0x00, 0x00, 0x00, 0x87000000);
    __m128i mask = _mm_setr_epi32(0x80, 0x00, 0x00, 0x00);

    //
    // R = Encrypt(K, 0...0)
    //

    temporary = _mm_setr_epi32(0x00, 0x00, 0x00, 0x00);
    cipher->encrypt_block(temporary, key, &R);

    //
    // If MSB(R) = 0, then K1 = (R << 1)
    // Else                K1 = (R << 1) + B128;
    //

    internal_subkey1 = cmacp_left_shift(R);

    if (!_mm_test_all_zeros(R, mask))
    {
        internal_subkey1 = _mm_xor_si128(internal_subkey1, B128);
    }

    subkey1->key = internal_subkey1;

    //
    // If MSB1(K1) = 0, then K2 = (K1 << 1)
    // Else                  K2 = (K1 << 1) + B128
    //

    internal_subkey2 = cmacp_left_shift(internal_subkey1);

    if (!_mm_test_all_zeros(internal_subkey1, mask))
    {
        internal_subkey2 = _mm_xor_si128(internal_subkey2, B128);
    }

    subkey2->key = internal_subkey2;
}


void cmac_digest(const unsigned char* in, unsigned long blocks,
                 const unsigned char* key, unsigned char* out,
                 const BLOCK_CIPHER* cipher)
{
    KEY internal_key;
    cipher->initialize_encrypt_key(key, &internal_key);

    cmac_digest_perform(in, blocks, &internal_key, out, cipher);
}


void cmac_digest_perform(const unsigned char* in, unsigned long blocks,
                         const KEY* key, unsigned char* out,
                         const BLOCK_CIPHER* cipher)
{
    unsigned int block;

    __m128i temporary;
    __m128i mac_mask;

    const __m128i* internal_in = (const __m128i*)in;
    __m128i* internal_out      = (__m128i*)out;

    //
    // Second subkey is not necessary here, because it used when a
    // last block of the message is incomplete. Here we assume
    // full disk encryption setting, so all blocks are complete.
    //

    CMACP_SUBKEY subkey1;
    CMACP_SUBKEY unused;

    cmacp_subkeys_init(key, &subkey1, &unused, cipher);

    //
    // Process first N - 1 blocks
    //

    temporary = _mm_setr_epi32(0x00, 0x00, 0x00, 0x00);

    for (block = 0; block < blocks - 1; ++block)
    {
        temporary = _mm_xor_si128(temporary, internal_in[block]);
        cipher->encrypt_block(temporary, key, &temporary);
    }

    //
    // Process the last block
    // It is additionall XOR-ed with the first subkey
    //

    temporary = _mm_xor_si128(temporary, subkey1.key);
    temporary = _mm_xor_si128(temporary, internal_in[block]);
    cipher->encrypt_block(temporary, key, &temporary);

    //
    // Now we need to truncate MAC to half of the block
    //

    mac_mask      = cmacp_mask();
    *internal_out = _mm_and_si128(temporary, mac_mask);
}


cmac_verify_result cmac_verify(const unsigned char* in, unsigned long blocks,
                               const unsigned char* key, const unsigned char* tag,
                               const BLOCK_CIPHER* cipher)
{
    KEY internal_key;
    cipher->initialize_encrypt_key(key, &internal_key);

    return cmac_verify_perform(in, blocks, &internal_key, tag, cipher);
}


cmac_verify_result cmac_verify_perform(const unsigned char* in, unsigned long blocks,
                                       const KEY* key, const unsigned char* tag,
                                       const BLOCK_CIPHER* cipher)
{
    //
    // Tag cannot have length greater than 128 bits (Kuznyechik block length)
    //

    __m128i new_tag;
    __m128i given_tag;
    __m128i difference;

    //
    // CMAC verification is very straightforward: just calculate tag for the
    // data and compare with
    //

    cmac_digest_perform(in, blocks, key, (unsigned char*)&new_tag, cipher);
    given_tag = _mm_loadu_si128((const __m128i*)tag);

    //
    // Now calculate difference between tags (it should have no bits set to 1)
    //

    difference = _mm_xor_si128(new_tag, given_tag);
    return _mm_test_all_zeros(difference, difference)
             ? cmac_valid
             : cmac_invalid;
}
