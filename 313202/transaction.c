


#include "transaction.h"
#include "access_set.h"
#include "logger.h"
#include "tm.h"

tx_t transaction_init(shared_mem* mem, bool is_ro)
{
    transaction_t* tx = malloc(sizeof(transaction_t));
    if ( tx == NULL ) 
        return invalid_tx;

    tx->read_only = is_ro;
    tx->seg_free_size = 0;
    tx->write_words.size = 0;
    tx->read_words.size = 0;

    batcher_enter(mem->batcher, tx);

    return (tx_t) tx;
}

bool transaction_check(shared_mem* mem, transaction_t* tx)
{
    size_t s = tx->write_words.size;
    log_debug("[%p] Abort - reverting %zu words", tx, s);
    for (size_t i = 0; i < s; i++)
    {
        bool s_i = tx->write_words.segment_indices[i];
        bool w_i = tx->write_words.word_indices[i];
        shared_mem_segment seg = mem->segments[s_i];
        char state = as_extract_state( atomic_load(&(seg.access_sets[w_i])) );
        if (state == INVALID_STATE)
            return false;
    }
    return true;
}

void transaction_add_word(transaction_t* tx, size_t s_i, size_t w_i, bool is_read)
{
    struct modified_words words = is_read ? tx->read_words : tx->write_words;
    size_t s = words.size;
    words.segment_indices[s] = s_i;
    words.word_indices[s] = w_i;
    words.size++;
}


void transaction_abort(shared_mem* mem, transaction_t* tx)
{
    size_t s = tx->write_words.size;
    log_debug("[%p] Abort - reverting %zu words", tx, s);
    for (size_t i = 0; i < s; i++)
    {
        bool s_i = tx->write_words.segment_indices[i];
        bool w_i = tx->write_words.word_indices[i];
        access_set_t as = mem->segments[s_i].access_sets[w_i];
        as_revert_write(as, tx);
    }
}