
#include "macros.h"
#include "vec.h"
#include "segment.h"
#include "word.h"
#include "access_set.h"
#include "logger.h"
#include "virtual.h"

#include <stdio.h>
#include <stdlib.h>

int segment_alloc(shared_mem* mem, size_t size)
{
    // create new mem segment
    shared_mem_segment* segment = malloc(sizeof(shared_mem_segment));
    if ( segment == NULL )
        return 1;

    segment->size = size;
    segment->words = calloc(size, sizeof(shared_mem_word)); 
    
    if ( unlikely( segment->words == NULL ) )
    {
        free(segment);
        return 1;
    }

    // initialize each word
    for (size_t i = 0; i < size; i++)
    {
        shared_mem_word* word = word_init(mem->align);
        if ( unlikely( word == NULL ) )
        {
            for (long j = i; j >= 0; j--)
                word_free(segment->words[j]);
            free(segment->words);
            free(segment);
            return 1;
        }
        segment->words[i] = *word;
    }

    mem->segments[mem->allocated_segments++] = *segment;
    return 0;
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
    for (size_t i = 0; i < seg.size; i++)
        word_free(seg.words[i]);
}