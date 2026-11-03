#ifndef CROSS_SYS_MMAN_H
#define CROSS_SYS_MMAN_H
#include <stddef.h>
int madvise(void *addr, size_t length, int advice);
#endif
