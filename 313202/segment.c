
#include "macros.h"
#include "vec.h"
#include "segment.h"
#include "word.h"
#include "access_set.h"
#include "logger.h"
#include "virtual.h"

#include <stdio.h>
#include <stdlib.h>

bool segment_alloc(shared_mem* mem, size_t size)
{
    shared_mem_segment seg; 

    seg.size = size;
    seg.access_sets = calloc(size, sizeof(access_set_t)); 
    seg.writeCopies = calloc(size, sizeof(void*)); 
    seg.readCopies = calloc(size, sizeof(void*)); 
    
    if ( unlikely( 
        seg.access_sets == NULL || 
        seg.writeCopies == NULL || 
        seg.readCopies == NULL 
    ) )
    {
        free(seg.access_sets);
        free(seg.writeCopies);
        free(seg.readCopies);
        return true;
    }

    for (size_t i = 0; i < size; i++)
    {
        seg.writeCopies[i] = calloc(1, mem->align);
        seg.readCopies[i] = calloc(1, mem->align);
    }

    mem->segments[mem->allocated_segments++] = seg;
    return false;
}

size_t get_segment_index( void const* addr )
{
    return (size_t) SEG_INDEX((uintptr_t) addr);
}


size_t get_word_index( void const* addr )
{
    return (size_t) WORD_INDEX((uintptr_t) addr);
}


void segment_free(shared_mem_segment seg)
{
    free(seg.access_sets);
    free(seg.writeCopies);
    free(seg.readCopies);
}