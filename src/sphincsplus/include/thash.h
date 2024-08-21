#ifndef SPX_THASH_H
#define SPX_THASH_H

#ifdef __cplusplus
extern "C"{
#endif
#include <stdint.h>

void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const unsigned char *pub_seed, uint32_t addr[8]);
#ifdef __cplusplus
}
#endif

#endif