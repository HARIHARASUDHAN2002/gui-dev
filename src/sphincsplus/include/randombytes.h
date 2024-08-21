#ifndef SPX_RANDOMBYTES_H_
#define SPX_RANDOMBYTES_H_

#ifdef __cplusplus
extern "C"{
#endif

extern void randombytes(unsigned char * x,unsigned long long xlen);
extern void ping_rbytes();

#ifdef __cplusplus
}
#endif

#endif
