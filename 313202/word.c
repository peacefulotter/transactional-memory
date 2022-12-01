
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#include "word.h"
#include "macros.h"
#include "access_set.h"
#include "vec.h"
#include "logger.h"
#include "tm.h"

size_t format( void* src, size_t size )
{
    size_t f = 0;
    memcpy(&f, src, size);
    return f;
}


size_t word_save_modif(shared_mem* mem, size_t s_i, size_t w_i, bool is_read)
{
    struct modified_words_lock w = is_read ? mem->modif_read : mem->modif_write;
    lock_acquire(w.lock);
    size_t idx = w.size;
    w.segment_indices[idx] = s_i;
    w.word_indices[idx] = w_i;
    w.size++;
    lock_release(w.lock);
    return idx;
}

void word_print(shared_mem* mem, transaction_t* tx, shared_mem_segment seg, size_t word_index)
{
    size_t s = atomic_load(&seg.access_sets[word_index]);
    void* read = seg.readCopies + word_index;
    void* write = seg.writeCopies + word_index;

    log_debug(
        "[%p] word_i=%zu, readCopy=(%p, %zu), writeCopy=(%p, %zu), access=(state=%zu, tx=%p)", 
        tx, word_index,
        read, format(read, mem->align),
        write, format(write, mem->align),
        as_extract_state(s), as_extract_tx(s)
    );
}