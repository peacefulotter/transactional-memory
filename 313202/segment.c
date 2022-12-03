
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "macros.h"
#include "vec.h"
#include "segment.h"
#include "word.h"
#include "access_set.h"
#include "logger.h"
#include "virtual.h"


bool segment_alloc(shared_mem* mem, size_t size)
{
    shared_mem_segment seg; 

    seg.size = size;
    seg.access_sets = calloc(size, sizeof(access_set_t)); 
    seg.writeCopies = calloc(size, mem->align);  
    seg.readCopies = calloc(size, mem->align);
    
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