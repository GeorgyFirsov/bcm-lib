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
    0x1f, 0x33, 0xd9, 0xd3, 0xfc, 0x06, 0x9f, 0x67, 
    0x81, 0xe1, 0x65, 0x9d, 0xeb, 0xc5, 0xa7, 0xaf, 
    0xfb, 0x50, 0xb8, 0xc6, 0x7a, 0xe6, 0xb2, 0x83, 
    0x9c, 0x7e, 0x43, 0x57, 0xcb, 0x51, 0x3f, 0xc3
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
