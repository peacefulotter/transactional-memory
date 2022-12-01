
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
#include "lock.h"

size_t format( void* src, size_t size )
{
    size_t f = 0;
    memcpy(&f, src, size);
    return f;
}

size_t word_save_read_modif(shared_mem* mem, size_t s_i, size_t w_i)
{
    lock_acquire(mem->modif_read.lock);
    size_t idx = mem->modif_read.size;
    mem->modif_read.segment_indices[idx] = s_i;
    mem->modif_read.word_indices[idx] = w_i;
    mem->modif_read.size++;
    lock_release(mem->modif_read.lock);
    return idx;
}

size_t word_save_write_modif(shared_mem* mem, size_t s_i, size_t w_i)
{
    lock_acquire(mem->modif_write.lock);
    size_t idx = mem->modif_write.size;
    mem->modif_write.segment_indices[idx] = s_i;
    mem->modif_write.word_indices[idx] = w_i;
    mem->modif_write.size++;
    lock_release(mem->modif_write.lock);
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