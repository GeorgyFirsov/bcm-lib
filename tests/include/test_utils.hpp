/**
 * @file test_utils.hpp
 * @brief Some helpers for tests.
 */

#pragma once

#include <cstddef>


//
// Necessary helper macro
//

#if defined(_MSC_VER)
#   define BCMLIB_TESTS_ALIGN16 __declspec(align(16))
#elif defined(__GNUC__) 
#   define BCMLIB_TESTS_ALIGN16 __attribute__ ((aligned(16)))
#else
#   error Unsupported target for now
#endif 


namespace test::details {

/**
 * @brief Test blocks for equality.
 */
inline bool EqualBlocks(const unsigned char* lhs, const unsigned char* rhs, std::size_t block_size)
{
    for (size_t idx = 0; idx < block_size; ++idx)
    {
        if (lhs[idx] != rhs[idx])
        {
            return false;
        }
    }

    return true;
}


/**
 * @brief Test data units for equality.
 */
inline bool EqualDataUnits(const unsigned char* lhs, const unsigned char* rhs, std::size_t blocks, std::size_t block_size)
{
    for (std::size_t idx = 0; idx < block_size * blocks; ++idx)
    {
        if (lhs[idx] != rhs[idx])
        {
            return false;
        }
    }

    return true;
}

}  // namespace test::details