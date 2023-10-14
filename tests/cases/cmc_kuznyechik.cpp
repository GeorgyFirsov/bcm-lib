/**
 * @file cmc_kuznyechik.cpp
 * @brief Test cases for Kuznyechik in CMC mode of operation.
 */

#include "test_common.hpp"


namespace test::data::enc {

/**
 * @brief Ciphertext for CMC-KUZNYECHIK algorithm.
 */
BCMLIB_TESTS_ALIGN16 static constexpr unsigned char ciphertext[] = {
    0xf2, 0x5b, 0x30, 0x56, 0xfa, 0x1f, 0x09, 0x8a,
    0x6a, 0x77, 0xe5, 0x66, 0x07, 0xc2, 0x15, 0x67,
    0x9a, 0xee, 0x76, 0xe6, 0x12, 0xe8, 0x35, 0x71,
    0x70, 0xa7, 0x18, 0xb0, 0xda, 0x94, 0x66, 0xcd
};

}  // namespace test::data::enc


TEST(CmcKuznyechik, Encrypt)
{
    using namespace test::data;

    //
    // MUST NOT throw any exception
    // Encrypted text MUST match an expected test vector
    //

    BLOCK_CIPHER cipher = {};
    kuznyechik_initialize_interface(&cipher);

    BCMLIB_TESTS_ALIGN16 unsigned char ciphertext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    cmc_encrypt(enc::tweak, enc::plaintext, enc::blocks, enc::primary_key,
                enc::secondary_key, ciphertext, &cipher);

    EXPECT_PRED4(test::details::EqualDataUnits, enc::ciphertext,
                 ciphertext, enc::blocks, KUZNYECHIK_BLOCK_SIZE);
}


TEST(CmcKuznyechik, Decrypt)
{
    using namespace test::data;

    //
    // MUST NOT throw any exception
    // Decrypted text MUST match an expected test vector
    //

    BLOCK_CIPHER cipher = {};
    kuznyechik_initialize_interface(&cipher);

    BCMLIB_TESTS_ALIGN16 unsigned char plaintext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    cmc_decrypt(enc::tweak, enc::ciphertext, enc::blocks, enc::primary_key,
                enc::secondary_key, plaintext, &cipher);

    EXPECT_PRED4(test::details::EqualDataUnits, enc::plaintext,
                 plaintext, enc::blocks, KUZNYECHIK_BLOCK_SIZE);
}
