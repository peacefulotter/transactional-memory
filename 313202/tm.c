/**
 * @file   tm.c
 * @author [...]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>

// Internal headers
#include "tm.h"
#include "macros.h"
#include "access_set.h"
#include "word.h"
#include "batcher.h"
#include "vec.h"
#include "segment.h"
#include "logger.h"
#include "virtual.h"

// TODO: compare and swap
// TODO: batcher atomic?

bool read_word(shared_mem_word word, void* read_to, transaction_t* tx, size_t word_size);
bool write_word(shared_mem_word word, const void* write_from, transaction_t* tx, size_t word_size);

void print_mem(shared_mem* mem)
{
    log_debug("=====================================");
    log_debug("mem.align: %zu", mem->align);
    size_t s = atomic_load(&mem->allocated_segments);
    log_debug("mem.allocated_segments: %zu", s);
    for (size_t i = 0; i < s; i++)
    {
        shared_mem_segment s = mem->segments[i];
        log_debug("segment nb %zu, segment size: %zu", i, s.size);
        for (size_t j = 0; j < 10; j++)
            word_print(NULL, s.words[j]);
        log_debug("----------------------");
    }
    log_debug("=====================================");
    // mem->batcher;
}


/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) {
    
    // log_set_quiet(true);

    log_info("===== tm_create start size: %zu, align: %zu", size, align);
    shared_mem* mem = malloc(sizeof(shared_mem));
    if ( unlikely(mem == NULL) ) 
        return invalid_shared;

    mem->align = align;
    mem->allocated_segments = 0;

    mem->batcher = get_batcher();
    if ( mem->batcher == NULL )
    {
        free(mem);
        return invalid_shared;
    } 

    if ( segment_alloc(mem, size) )
    {
        batcher_free(mem->batcher);
        mem->batcher = NULL;
        free(mem);
        return invalid_shared;
    }

    print_mem(mem);
    return mem;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) {
    log_info("tm_destroy start\n");
    shared_mem* mem = (shared_mem*) shared;
    
    batcher_free(mem->batcher);

    size_t nb = atomic_load(&mem->allocated_segments);
    for (size_t i = 0; i < nb; i++)
        segment_free(mem->segments[i]);
    
    mem->allocated_segments = 0;
    mem->align = 0;

    log_info("tm_destroy end\n");
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t unused(shared)) {
    return SEG_ADDR(1LL);
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) {
    return ((shared_mem*) shared)->segments[0].size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) {
    return ((shared_mem*) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) 
{
    shared_mem* mem = (shared_mem*) shared;

    transaction_t* tx = malloc(sizeof(transaction_t));
    if ( tx == NULL ) 
        return invalid_tx;

    tx->read_only = is_ro;
    tx->seg_free_vec = vector_create();
    tx->written_word_vec = vector_create();

    // TODO: not per tx but per thread 
    // batcher.blocked => vector to set
    batcher_enter(mem->batcher);

    return (tx_t) tx;
}

bool swap(void *a, void *b, size_t width)
{
    void *temp = malloc(width);
    if ( temp == NULL ) return false;
    memcpy(temp, b, width);
    memcpy(b, a, width);
    memcpy(a, temp, width);
    free(temp);
    return true;
}


bool commit( shared_mem* mem, transaction_t* tx )
{
    log_info("[%p]  commit  start", tx);

    size_t s = vector_size(tx->written_word_vec);
    for (size_t i = 0; i < s; i++)
    {
        shared_mem_word* w = tx->written_word_vec[i];
        if ( !swap(w->readCopy, w->writeCopy, mem->align) )
            return false;

        // 3 -> 0 if word written
        char write_state = WRITE_STATE;
        atomic_compare_exchange_strong(&w->access_set->state, &write_state, INIT_STATE);
    }
    vector_free(tx->written_word_vec); 

    log_info("[%p]  commit  end", tx);
    return true;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) {
    log_info("[%p]  tm_end  start", tx);

    shared_mem* mem = (shared_mem*) shared;
    transaction_t* transaction = (transaction_t*) tx;


    // leave batcher - no more threads remaining => commit
    batcher* b = mem->batcher;
    if ( batcher_leave(b) ) 
        commit(mem, transaction);
        // TODO: also reset all words access_set to INIT_STATE

    // free the segments 
    size_t s = vector_size(transaction->seg_free_vec);
    for (size_t i = 0; i < s; i++)
        segment_free(*transaction->seg_free_vec[i]);
    vector_free(transaction->seg_free_vec);   


    log_info("[%p]  tm_end  end", tx);
    return true;
}

bool read_word(shared_mem_word w, void* read_to, transaction_t* tx, size_t word_size)
{
    if ( tx->read_only )
    {
        memcpy(read_to, w.readCopy, word_size);
        return true;
    }
    
    else if ( as_read_op(w.access_set, tx) )
    {
        char state = atomic_load(&w.access_set->state);
        if ( state == WRITE_STATE )
            memcpy(read_to, w.writeCopy, word_size);
        else if ( state == READ_STATE || state == DOUBLE_READ_STATE )
            memcpy(read_to, w.readCopy, word_size);
        return true;
    }

    return false;
}


/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target) {
    shared_mem* mem = (shared_mem*) shared;
    transaction_t* transaction = (transaction_t*) tx;

    size_t seg_index = get_segment_index(source);
    size_t word_index = get_word_index(source);

    log_info("[%p]  tm_read  start (%zu, %zu)", tx, seg_index, word_index);

    size_t a = mem->align;
    shared_mem_segment seg = mem->segments[seg_index];
    for (size_t offset = 0; offset < size / a; offset++)
    {
        shared_mem_word word = seg.words[word_index + offset];
        if ( !read_word(word, target + offset * a, transaction, a) )
        {
            log_error("[%p] read failed", tx);
            return false;
        }
    }

    return true;
}


bool write_word(shared_mem_word w, const void* src, transaction_t* tx, size_t word_size)
{
    if ( as_write_op(w.access_set, tx) )
    {
        memcpy(w.writeCopy, src, word_size);
        return true;
    }

    return false;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* target) 
{
    shared_mem* mem = (shared_mem*) shared;
    transaction_t* transaction = (transaction_t*) tx;

    size_t seg_index = get_segment_index(target);
    size_t word_index = get_word_index(target); 

    log_info("[%p]  tm_write  target: %p, (%zu, %zu), size: %zu", tx, target, seg_index, word_index, size);

    size_t a = mem->align;
    shared_mem_segment seg = mem->segments[seg_index];
    for (size_t offset = 0; offset < size / a; offset++)
    {
        shared_mem_word word = seg.words[word_index + offset];
        word_print(transaction, word);
        if ( !write_word(word, source + offset * a, transaction, a) ) 
        {
            log_error("[%p] write failed", tx);
            return false;
        }
        vector_add(&transaction->written_word_vec, &word);
    }

    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t shared, tx_t tx, size_t size, void** target) {
    log_debug("[%p]  tm_alloc  start", tx);
    shared_mem* mem = (shared_mem*) shared;

    if ( segment_alloc(mem, size) )
        return nomem_alloc;

    *target = SEG_ADDR(mem->allocated_segments);

    log_debug("[%p]  tm_alloc  end, target=%p", tx, *target);

    return success_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared, tx_t tx, void* target) {
    log_debug("tm_free start\n");

    // shared_mem* mem = (shared_mem*) shared;
    shared_mem_segment* segment = (shared_mem_segment*) target;
    transaction_t* transaction = (transaction_t*) tx;

    vector_add(&transaction->seg_free_vec, segment);

    log_debug("tm_free end\n");
    return true;
}
