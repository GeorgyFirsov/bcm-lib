/**
 * @file xts_kuznyechik.cpp
 * @brief Test cases for Kuznyechik in XTS mode of operation.
 */

#include "test_common.hpp"


namespace test::data {

/**
 * @brief Ciphertext for XTS-KUZNYECHIK algorithm.
 */
BCMLIB_TESTS_ALIGN16 static constexpr unsigned char ciphertext[] = {
    0x29, 0x1f, 0x33, 0x6f, 0x0d, 0x92, 0x87, 0xce, 
    0x92, 0x1f, 0x2b, 0x33, 0x24, 0xf3, 0x45, 0xe6, 
    0x22, 0xf6, 0x85, 0x60, 0xe6, 0x7e, 0x90, 0x24, 
    0x71, 0x27, 0x4a, 0x5f, 0x3a, 0x05, 0x06, 0x77
};

}  // namespace test::data


TEST(XtsKuznyechik, Encrypt)
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

    xts_encrypt(test::data::tweak, test::data::plaintext, test::data::blocks,
                test::data::primary_key, test::data::secondary_key, ciphertext, &cipher);
    
    EXPECT_PRED4(test::details::EqualDataUnits, test::data::ciphertext, ciphertext,
                 test::data::blocks, KUZNYECHIK_BLOCK_SIZE);
}


TEST(XtsKuznyechik, Decrypt)
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

    xts_decrypt(test::data::tweak, test::data::ciphertext, test::data::blocks,
                test::data::primary_key, test::data::secondary_key, plaintext, &cipher);

    EXPECT_PRED4(test::details::EqualDataUnits, test::data::plaintext, plaintext,
                 test::data::blocks, KUZNYECHIK_BLOCK_SIZE);
}
