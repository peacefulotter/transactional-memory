
#include "tm.h"

#define _POSIX_C_SOURCE 200809L

shared_mem_segment segment_alloc(shared_mem* mem, size_t size);
void segment_free(shared_mem_segment* seg);
