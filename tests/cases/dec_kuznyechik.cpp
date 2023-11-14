/**
 * @file dec_kuznyechik.cpp
 * @brief Test cases for Kuznyechik in DEC mode of operation.
 */

#include "test_common.hpp"


namespace test::data::enc {

/**
 * 
 */
static constexpr auto partition = tweak;
static constexpr auto sector    = tweak;

/**
 * 
 */
static constexpr auto partition_counter = 0xcafebabe;
static constexpr auto sector_counter    = 0xdeadbeef;

/**
 * @brief Ciphertext for DEC-KUZNYECHIK algorithm.
 */
BCMLIB_TESTS_ALIGN16 static constexpr unsigned char ciphertext[] = {
    0xe6, 0x3d, 0x36, 0x20, 0x98, 0x10, 0xbe, 0x6f,
    0xb9, 0x16, 0xca, 0x61, 0xee, 0x0a, 0x9c, 0xc6,
    0x79, 0xb8, 0x29, 0xe6, 0xe3, 0x4d, 0xc6, 0xf3,
    0x5b, 0x4f, 0x37, 0x54, 0x28, 0xd6, 0x78, 0x5f
};

}  // namespace test::data::enc


TEST(DecKuznyechik, Encrypt)
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

    dec_encrypt(enc::partition, enc::partition_counter, enc::sector, enc::sector_counter,
                enc::plaintext, enc::blocks, enc::primary_key, ciphertext, &cipher);

    for (auto c : ciphertext)
    {
//printf("0x%02x, ", c);
    }

    EXPECT_PRED4(test::details::EqualDataUnits, enc::ciphertext,
                 ciphertext, enc::blocks, KUZNYECHIK_BLOCK_SIZE);
}


TEST(DecKuznyechik, Decrypt)
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

    dec_decrypt(enc::partition, enc::partition_counter, enc::sector, enc::sector_counter,
                enc::ciphertext, enc::blocks, enc::primary_key, plaintext, &cipher);

for (auto c : plaintext)
    {
     //   printf("0x%02x, ", c);
    }

    EXPECT_PRED4(test::details::EqualDataUnits, enc::plaintext,
                 plaintext, enc::blocks, KUZNYECHIK_BLOCK_SIZE);
}
