
#pragma once

#include "tm.h"

#define _POSIX_C_SOURCE 200809L

bool segment_alloc(shared_mem* mem, size_t size);
size_t get_segment_index( void const* addr );
size_t get_word_index( void const* addr );
void segment_free(shared_mem_segment seg);
