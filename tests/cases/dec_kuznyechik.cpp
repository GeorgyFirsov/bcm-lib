/**
 * @file dec_kuznyechik.cpp
 * @brief Test cases for Kuznyechik in DEC mode of operation.
 */

#include "test_common.hpp"


namespace test::data::enc {

/**
 * @brief Partition and sector numbers for DEC-KUZNYECHIK algorithm.
 */
static constexpr auto partition = tweak;
static constexpr auto sector    = tweak;


/**
 * @brief Partition and sector counters for DEC-KUZNYECHIK algorithm.
 */
static constexpr auto partition_counter = 0xcafebabe;
static constexpr auto sector_counter    = 0xdeadbeef;


/**
 * @brief Ciphertext for DEC-KUZNYECHIK algorithm.
 */
BCMLIB_TESTS_ALIGN16 static constexpr unsigned char ciphertext[] = {
    0x46, 0x1f, 0xfb, 0x9e, 0x05, 0x9b, 0xa4, 0x42, 
    0xfe, 0x8a, 0xcc, 0xa5, 0x04, 0xb5, 0x50, 0x04, 
    0x7d, 0x22, 0x84, 0x41, 0xdf, 0x44, 0x9d, 0xd9, 
    0x07, 0x7f, 0x76, 0xce, 0xc9, 0x37, 0x09, 0x03
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

    EXPECT_PRED4(test::details::EqualDataUnits, enc::plaintext,
                 plaintext, enc::blocks, KUZNYECHIK_BLOCK_SIZE);
}
