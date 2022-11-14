
#include "vec.h"
#include "segment.h"
#include "word.h"
#include "access_set.h"

#include <stdio.h>
#include <stdlib.h>


shared_mem_segment segment_alloc(shared_mem* mem, size_t size)
{
    printf("--- alloc_new_segment start, size: %zu \n", size);

    // create new mem segment
    shared_mem_segment segment = calloc(size, mem->align); 
    if ( segment == NULL )
        return NULL;
    
    // if ( posix_memalign((void**)&segment, mem->align, size) != 0 )
    //     return NULL;

    printf("segment: %p\n", segment);

    // initialize each word
    for (size_t i = 0; i < size; i++)
    {
        shared_mem_word* word = initialize_word(mem->align);
        if ( word == NULL )
        {
            for (long j = i - 1; j >= 0; j--)
                release_word(&segment[j]);
            free( segment );
            return NULL;
        }
        segment[i] = *word;
    }

    vector_add(&mem->segment_sizes_vec, size);
    vector_add(&mem->segments_vec, segment);

    printf("mem->segments %zu\n", vector_size(mem->segments_vec));
    printf("mem->segment_sizes %zu \n", vector_size(mem->segment_sizes_vec));

    printf("--- alloc_new_segment stop\n");
    return segment;
}

void segment_free(shared_mem_segment* seg)
{
    for (size_t i = 0; i < vector_size(seg); i++)
        release_word(&(*seg)[i]);
    free(seg);
    // free(mem->segments); TODO: vec->remove(seg)
}