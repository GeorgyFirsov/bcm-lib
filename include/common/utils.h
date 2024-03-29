/**
 * @file utils.h
 * @brief Some useful helper things.
 */

#ifndef BCMLIB_UTILS_INCLUDED
#define BCMLIB_UTILS_INCLUDED


/**
 * @brief Alignment specifier (alignas is supported since C11).
 */
#if defined(_MSC_VER)
#   define BCMLIB_ALIGN16 __declspec(align(16))
#elif defined(__GNUC__)
#   define BCMLIB_ALIGN16 __attribute__((aligned(16)))
#else
#   error Unsupported target for now
#endif


/**
 * @brief Force inlining specifier.
 */
#if defined(_MSC_VER)
#   define BCMLIB_FORCEINLINE __forceinline
#elif defined(__GNUC__)
#   define BCMLIB_FORCEINLINE __attribute__((always_inline))
#else
#   error Unsupported target for now
#endif


/**
 * @brief Static assertion for C language (prior to C11).
 */
#define BCMLIB_STATIC_ASSERT(cond, msg) \
    typedef char static_assertion_failed_##msg[(cond) ? 1 : -1]


/**
 * @brief Macro to suppress unused variable warning.
 */
#define BCMLIB_UNUSED(var) ((void)(var))


/**
 * @brief Returns number of elements in a static array.
 */
#define BCMLIB_COUNTOF(arr) (sizeof((arr)) / sizeof((arr)[0]))


/**
 * @brief Swaps byte order in arbitrary integer type inplace.
 */
#define BCMLIB_SWAP_ENDIAN_INPLACE(value)                                                                        \
    do                                                                                                           \
    {                                                                                                            \
        unsigned char* bsw_internal_value = (unsigned char*)&value;                                              \
        for (unsigned long long idx = 0, swp_idx = sizeof(value) - 1; idx < sizeof(value) / 2; ++idx, --swp_idx) \
        {                                                                                                        \
            bsw_internal_value[idx]     = bsw_internal_value[idx] ^ bsw_internal_value[swp_idx];                 \
            bsw_internal_value[swp_idx] = bsw_internal_value[idx] ^ bsw_internal_value[swp_idx];                 \
            bsw_internal_value[idx]     = bsw_internal_value[idx] ^ bsw_internal_value[swp_idx];                 \
        }                                                                                                        \
    }                                                                                                            \
    while (0)


/**
 * @brief Swaps byte order of a `long long` value.
 */
long long bcmlib_swap_endian_ll(long long value);


#endif  // !BCMLIB_UTILS_INCLUDED
