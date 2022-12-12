

#include <stdlib.h>

#include "mem.h"
#include "lock.h"
#include "transaction.h"
#include "access_set.h"
#include "batcher.h"
#include "logger.h"
#include "tm.h"

tx_t transaction_init(shared_mem* mem, bool is_ro)
{
    transaction_t* tx = malloc(sizeof(transaction_t));
    if ( tx == NULL ) 
        return invalid_tx;

    tx->read_only = is_ro;
    tx->seg_free_size = 0;
    tx->write_size = 0;

    batcher_enter(mem->batcher, tx);

    return (tx_t) tx;
}

void tx_register_write_word(transaction_t* tx, size_t idx)
{
    tx->write_words_indices[tx->write_size++] = idx;
}

void tx_abort(shared_mem* mem, transaction_t* tx)
{
    // TODO: free allocated segments
  
    // TODO: don't care if very slow 
    // if more than 2>>16 alloc -> find free segments

    lock_acquire(mem->batcher->block);
    batcher_block_entry(mem->batcher);
    lock_release(mem->batcher->block);

    if ( tx->read_only )
        return;

    size_t* w = tx->write_words_indices;
    size_t s = tx->write_size;
    // log_debug("[%p] Abort - reverting %zu written words", tx, s);
    for (size_t i = 0; i < s; i++)
    {
        size_t idx = w[i];
        size_t s_i = mem->modif_write.segment_indices[idx];
        size_t w_i = mem->modif_write.word_indices[idx];
        shared_mem_segment seg = mem->segments[s_i];
        // log_error("[%p] idx: %zu, s_i: %zu, w_i: %zu", tx, idx, s_i, w_i);
        as_revert_write(seg.access_sets + w_i, tx);
    }
    tx->write_size = 0;
}