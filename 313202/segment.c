
#include "vec.h"
#include "segment.h"
#include "word.h"
#include "access_set.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>

int segment_alloc(shared_mem* mem, size_t size)
{
    printf("--- alloc_new_segment start, size: %zu \n", size);

    // create new mem segment
    shared_mem_segment* segment = malloc(sizeof(shared_mem_segment));
    if ( segment == NULL )
        return 1;

    segment->size = size;
    segment->words = calloc(size, mem->align); 
    
    if ( segment->words == NULL )
    {
        free(segment);
        return 1;
    }

    // initialize each word
    for (size_t i = 0; i < size; i++)
    {
        shared_mem_word* word = word_init(mem->align);
        if ( word == NULL )
        {
            for (long j = i - 1; j >= 0; j--)
                word_free(segment->words[j]);
            free( segment->words );
            free( segment );
            return 1;
        }
        segment->words[i] = *word;
    }

    mem->segments[mem->allocated_segments++] = *segment;

    printf("--- alloc_new_segment stop\n");
    return 0;
}

size_t get_segment_index( void const* addr )
{
    size_t s = *((size_t*) addr);
    size_t seg_index = s >> 48 - 1;
    log_info("addr: %p, seg_index: %zu", addr, seg_index);
    return seg_index;
}


size_t get_word_index( void const* addr )
{
    size_t s = *((size_t*) addr);
    size_t word_index = s & 0xFFFF;
    log_info("addr: %p, word_index: %zu", addr, word_index);
    return word_index;
}


void segment_free(shared_mem_segment seg)
{
    for (size_t i = 0; i < seg.size; i++)
        word_free(seg.words[i]);
}