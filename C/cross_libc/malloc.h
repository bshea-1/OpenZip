#ifndef CROSS_MALLOC_H
#define CROSS_MALLOC_H
#include <stdlib.h>
void *_aligned_malloc(size_t size, size_t alignment);
void _aligned_free(void *memblock);
#endif
