#include <stdint.h>
#include <string.h>

#include "../include/thash.h"
#include "../include/address.h"
#include "../include/params.h"

#include "../include/fips202.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash_robust(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];
    unsigned char bitmask[inblocks * SPX_N];
    unsigned int i;

    memcpy(buf, pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);

    shake256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_ADDR_BYTES);

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
}