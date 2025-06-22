#ifndef SHA3_H
#define SHA3_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

void sha3_256(uint8_t *hash, const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
