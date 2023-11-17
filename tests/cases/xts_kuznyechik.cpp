/**
 * @file xts_kuznyechik.cpp
 * @brief Test cases for Kuznyechik in XTS mode of operation.
 */

#include "test_common.hpp"


namespace test::data::enc {

/**
 * @brief Ciphertext for XTS-KUZNYECHIK algorithm.
 */
BCMLIB_TESTS_ALIGN16 static constexpr unsigned char ciphertext[] = {
    0x29, 0x1f, 0x33, 0x6f, 0x0d, 0x92, 0x87, 0xce,
    0x92, 0x1f, 0x2b, 0x33, 0x24, 0xf3, 0x45, 0xe6,
    0x22, 0xf6, 0x85, 0x60, 0xe6, 0x7e, 0x90, 0x24,
    0x71, 0x27, 0x4a, 0x5f, 0x3a, 0x05, 0x06, 0x77
};

}  // namespace test::data::enc


TEST(XtsKuznyechik, Encrypt)
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

    xts_encrypt(enc::tweak, enc::plaintext, enc::blocks, enc::primary_key,
                enc::secondary_key, ciphertext, &cipher);

    EXPECT_PRED4(test::details::EqualDataUnits, enc::ciphertext,
                 ciphertext, enc::blocks, KUZNYECHIK_BLOCK_SIZE);
}


TEST(XtsKuznyechik, Decrypt)
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

    xts_decrypt(enc::tweak, enc::ciphertext, enc::blocks, enc::primary_key,
                enc::secondary_key, plaintext, &cipher);

    EXPECT_PRED4(test::details::EqualDataUnits, enc::plaintext,
                 plaintext, enc::blocks, KUZNYECHIK_BLOCK_SIZE);
}
