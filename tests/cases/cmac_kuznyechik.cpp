/**
 * @file cmac_kuznyechik.cpp
 * @brief Test cases for Kuznyechik in CMAC mode of operation.
 */

#include "test_common.hpp"


namespace test::data::mac {

/**
 * @brief Digest for CMAC-KUZNYECHIK algorithm.
 */
BCMLIB_TESTS_ALIGN16 static constexpr unsigned char digest[] = {
    0x33, 0x6f, 0x4d, 0x29, 0x60, 0x59, 0xfb, 0xe3,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/**
 * @brief Incorrect digest for CMAC-KUZNYECHIK algorithm.
 */
BCMLIB_TESTS_ALIGN16 static constexpr unsigned char incorrect_digest[] = {
    0x34, 0x6e, 0x4e, 0x28, 0x61, 0x58, 0xfc, 0xe4,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

}  // namespace test::data::mac


TEST(CmacKuznyechik, Digest)
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

    unsigned char digest[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    cmac_digest(mac::data, mac::blocks, mac::key, digest, &cipher);

    EXPECT_PRED3(test::details::EqualBlocks, mac::digest, digest,
                 KUZNYECHIK_BLOCK_SIZE);
}


TEST(CmacKuznyechik, VerifyCorrect)
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

    const auto result = cmac_verify(mac::data, mac::blocks, mac::key,
                                    mac::digest, &cipher);

    EXPECT_EQ(result, cmac_verify_result::cmac_valid);
}


TEST(CmacKuznyechik, VerifyIncorrect)
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

    const auto result = cmac_verify(mac::data, mac::blocks, mac::key,
                                    mac::incorrect_digest, &cipher);

    EXPECT_EQ(result, cmac_verify_result::cmac_invalid);
}
