
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#include "word.h"
#include "macros.h"
#include "access_set.h"
#include "vec.h"
#include "logger.h"
#include "mem.h"
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

size_t word_print(shared_mem* mem, transaction_t* tx, segment seg, size_t w_i)
{
    size_t s = atomic_load(&seg.access_sets[w_i]);
    void* read = seg.readCopies + w_i * mem->align;
    void* write = seg.writeCopies + w_i * mem->align;

    log_debug(
        "[%p] w_i=%zu, readCopy=(%p, %zu), writeCopy=(%p, %zu), access=(state=%zu, tx=%p)", 
        tx, w_i,
        read, format(read, mem->align),
        write, format(write, mem->align),
        as_extract_state(s), as_extract_tx(s)
    );
    return format(read, mem->align);
}