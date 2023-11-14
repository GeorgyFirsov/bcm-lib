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
    0x6a, 0xc5, 0x6d, 0x76, 0x40, 0xb8, 0x95, 0xac,
    0x78, 0x3b, 0xd6, 0x24, 0x8a, 0x53, 0x59, 0x3a, 
    0x79, 0xd9, 0xbe, 0x29, 0xf8, 0x65, 0x15, 0x71, 
    0xbb, 0xd6, 0xda, 0x32, 0x59, 0x51, 0x88, 0x75
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
