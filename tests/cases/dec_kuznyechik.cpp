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
    0x7c, 0x03, 0x84, 0x59, 0x53, 0xde, 0xdd, 0x3a, 
    0xe2, 0x8f, 0xde, 0xd7, 0x99, 0xe3, 0xed, 0x9f,
    0x77, 0x02, 0x77, 0xb9, 0x33, 0x75, 0x29, 0x13, 
    0x87, 0x8e, 0xae, 0x66, 0x2a, 0x57, 0x8b, 0xff
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
