/**
 * @file heh_kuznyechik.cpp
 * @brief Test cases for Kuznyechik in HEH mode of operation.
 */

#include "test_common.hpp"


namespace test::data {

/**
 * @brief Ciphertext for HEH-KUZNYECHIK algorithm.
 */
BCMLIB_TESTS_ALIGN16 static constexpr unsigned char ciphertext[] = {
    0x84, 0xda, 0x91, 0x40, 0x5f, 0x93, 0x44, 0xea, 
    0xcc, 0x7e, 0x93, 0x8e, 0x5a, 0xd6, 0xc6, 0xec, 
    0xce, 0x11, 0x8d, 0x3f, 0x18, 0x15, 0x40, 0x84,
    0x9e, 0xb8, 0xd7, 0x0a, 0x5b, 0xcf, 0x4d, 0xbe
};

}  // namespace test::data


TEST(HehKuznyechik, Encrypt)
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

    heh_encrypt(test::data::tweak, test::data::plaintext, test::data::blocks,
                test::data::primary_key, ciphertext, &cipher);
    
    EXPECT_PRED4(test::details::EqualDataUnits, test::data::ciphertext, ciphertext,
                 test::data::blocks, KUZNYECHIK_BLOCK_SIZE);
}


TEST(HehKuznyechik, Decrypt)
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

    heh_decrypt(test::data::tweak, test::data::ciphertext, test::data::blocks,
                test::data::primary_key, plaintext, &cipher);

    EXPECT_PRED4(test::details::EqualDataUnits, test::data::plaintext, plaintext,
                 test::data::blocks, KUZNYECHIK_BLOCK_SIZE);
}
