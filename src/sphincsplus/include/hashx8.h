#ifndef SPX_HASHX8_H
#define SPX_HASHX8_H

#ifdef __cplusplus
extern "C"{
#endif

#include <stdint.h>

void prf_addrx8(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                unsigned char *out4,
                unsigned char *out5,
                unsigned char *out6,
                unsigned char *out7,
                const unsigned char *key,
                const uint32_t addrx4[8*8]);

#ifdef __cplusplus
}
#endif

#endif
