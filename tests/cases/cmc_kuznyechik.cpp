/**
 * @file cmc_kuznyechik.cpp
 * @brief Test cases for Kuznyechik in CMC mode of operation.
 */

#include "test_common.hpp"


namespace test::data {

/**
 * @brief Ciphertext for CMC-KUZNYECHIK algorithm.
 */
BCMLIB_TESTS_ALIGN16 static constexpr unsigned char ciphertext[] = {
    0xf2, 0x5b, 0x30, 0x56, 0xfa, 0x1f, 0x09, 0x8a, 
    0x6a, 0x77, 0xe5, 0x66, 0x07, 0xc2, 0x15, 0x67, 
    0x9a, 0xee, 0x76, 0xe6, 0x12, 0xe8, 0x35, 0x71, 
    0x70, 0xa7, 0x18, 0xb0, 0xda, 0x94, 0x66, 0xcd
};

}  // namespace test::data


TEST(CmcKuznyechik, Encrypt)
{
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

    cmc_encrypt(test::data::tweak, test::data::plaintext, test::data::blocks,
                test::data::primary_key, test::data::secondary_key, ciphertext, &cipher);

    EXPECT_PRED4(test::details::EqualDataUnits, test::data::ciphertext, ciphertext,
                 test::data::blocks, KUZNYECHIK_BLOCK_SIZE);
}


TEST(CmcKuznyechik, Decrypt)
{
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

    cmc_decrypt(test::data::tweak, test::data::ciphertext, test::data::blocks,
                test::data::primary_key, test::data::secondary_key, plaintext, &cipher);

    EXPECT_PRED4(test::details::EqualDataUnits, test::data::plaintext, plaintext,
                 test::data::blocks, KUZNYECHIK_BLOCK_SIZE);
}
