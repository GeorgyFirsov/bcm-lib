/**
 * @file utils.c
 * @brief Some useful helper things.
 */

#include "common/utils.h"


long long bcmlib_swap_endian_ll(long long value)
{
    BCMLIB_SWAP_ENDIAN_INPLACE(value);
    return value;
}
