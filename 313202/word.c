
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>

#include "word.h"
#include "macros.h"
#include "access_set.h"
#include "vec.h"
#include "logger.h"

size_t format( void* p )
{
    if ( p == NULL ) // p == NULL 
        return 0;
    return *(size_t*)p;
}

// TODO: delete
void word_print(transaction_t* tx, shared_mem_segment seg, size_t word_index)
{
    size_t s = atomic_load(&seg.access_sets[word_index]);
    void* read = seg.readCopies[word_index];
    void* write = seg.writeCopies[word_index];
    log_debug(
        "[%p] word_i=%zu, readCopy=(%p, %zu), writeCopy=(%p, %zu), access=(state=%zu, tx=%p)", 
        tx, word_index,
        read, format(read),
        write, format(write),
        as_extract_state(s), as_extract_tx(s)
    );
}