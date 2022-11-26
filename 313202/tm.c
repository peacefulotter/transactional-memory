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
#include "word.h"
#include "batcher.h"
#include "vec.h"
#include "segment.h"
#include "logger.h"
#include "virtual.h"
#include "access_set.h"

bool read_word(shared_mem_segment seg, size_t w_i, void* read_to, transaction_t* tx, size_t word_size);
bool write_word(shared_mem_segment seg, size_t w_i, const void* write_from, transaction_t* tx, size_t word_size);

void print_mem(shared_mem* mem)
{
    return;
    log_debug("=====================================");
    log_debug("mem.align: %zu", mem->align);
    size_t s = atomic_load(&mem->allocated_segments);
    log_debug("mem.allocated_segments: %zu", s);
    for (size_t i = 0; i < s; i++)
    {
        shared_mem_segment s = mem->segments[i];
        log_debug("segment nb %zu, segment size: %zu", i, s.size);
        for (size_t j = 0; j < 10; j++)
            word_print(NULL, s, j);
        log_debug("----------------------");
    }
    batcher_print(mem->batcher);
    log_debug("=====================================");
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

    mem->modif_read.lock = malloc(sizeof(struct lock_t));
    if ( mem->modif_read.lock == NULL )
        goto fail_tm_create;

    mem->modif_write.lock = malloc(sizeof(struct lock_t));
    if ( mem->modif_write.lock == NULL )
        goto fail_tm_create;

    mem->batcher = get_batcher();
    if ( mem->batcher == NULL )
        goto fail_tm_create;

    if ( segment_alloc(mem, size) )
        goto fail_tm_create;

    mem->modif_read.size = 0;
    mem->modif_write.size = 0;
    lock_init(mem->modif_read.lock);
    lock_init(mem->modif_write.lock);

    print_mem(mem);
    return mem;

fail_tm_create: 
    free(mem->modif_write.lock);
    free(mem->modif_read.lock);
    batcher_free(mem->batcher);
    free(mem);
    return invalid_shared;
}

    

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) {
    log_info("tm_destroy start\n");
    shared_mem* mem = (shared_mem*) shared;
    
    batcher_free(mem->batcher);
    mem->batcher = NULL;

    size_t nb = mem->allocated_segments;
    for (size_t i = 0; i < nb; i++)
        segment_free(mem->segments[i]);

    free(mem->modif_read.lock);
    free(mem->modif_write.lock);
    
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
    tx->seg_free_size = 0;

    batcher_enter(mem->batcher, tx);

    return (tx_t) tx;
}

bool swap(void *a, void *b, size_t width)
{
    // TODO: only write to readCopy
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
    // swap written words
    lock_acquire(mem->modif_write.lock);
    size_t write_size = mem->modif_write.size;
    log_info("[%p]  commit  start, written word=%zu", tx, write_size);
    for (size_t i = 0; i < write_size; i++)
    {
        size_t s_i = mem->modif_write.segment_indices[i];
        size_t w_i = mem->modif_write.word_indices[i];
        shared_mem_segment seg = mem->segments[s_i];

        if ( 
            seg.access_sets[w_i] != INVALID_STATE && 
            !swap(seg.readCopies[w_i], seg.writeCopies[w_i], mem->align) 
        )
            return false;

        as_reset(&seg.access_sets[w_i]);
    }
    mem->modif_write.size = 0;
    lock_release(mem->modif_write.lock); 

    // reset access set of read words
    lock_acquire(mem->modif_read.lock);
    size_t read_size = mem->modif_read.size;
    log_info("[%p]  commit  part2, read word=%zu", tx, read_size);
    for (size_t i = 0; i < read_size; i++)
    {
        size_t s_i = mem->modif_write.segment_indices[i];
        size_t w_i = mem->modif_write.word_indices[i];
        shared_mem_segment seg = mem->segments[s_i];
        as_reset(&seg.access_sets[w_i]);
    }
    mem->modif_read.size = 0;
    lock_release(mem->modif_read.lock);

    log_info("[%p]  commit  end", tx);
    return true;
}


// leave batcher - no more threads remaining => commit
// returns true if commited succesfully or not allow to commit (not last tx on batcher)
bool leave_and_commit(shared_mem* mem, transaction_t* tx)
{
    bool committed = true;
    batcher* b = mem->batcher;
    if ( batcher_leave(b, tx) ) 
    {
        log_warn("[%p]  tm_end  Committing...", tx);
        committed = commit(mem, tx);
        log_warn("[%p]  tm_end  Finished commit worked=%u", tx, committed);
        print_mem(mem);
        batcher_wake_up(b);
    }
    return committed;
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

    bool committed = leave_and_commit(mem, transaction);

    // free the segments 
    // TODO: not sure about this
    size_t s = transaction->seg_free_size;
    for (size_t i = 0; i < s; i++)
        segment_free(*transaction->seg_free[i]);
    transaction->seg_free_size = 0;   

    log_info("[%p]  tm_end  end, commited=%u", tx, committed);
    return committed;
}

bool read_word(shared_mem_segment seg, size_t w_i, void* read_to, transaction_t* tx, size_t word_size)
{
    if ( tx->read_only )
        memcpy(read_to, seg.readCopies[w_i], word_size);
    else
    {
        // TODO: not atomic - lock barrier no matter what?
        char state = as_read_op(&seg.access_sets[w_i], tx);
        if ( state == INVALID_STATE )
            return false;
        if ( state == WRITE_STATE )
            memcpy(read_to, seg.writeCopies[w_i], word_size);
        else if ( state == READ_STATE || state == DOUBLE_READ_STATE )
            memcpy(read_to, seg.readCopies[w_i], word_size);
    }

    return true;
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

    size_t s_i = get_segment_index(source);
    size_t base_w_i = get_word_index(source);

    // log_info(" [%p]  tm_read  start (%zu, %zu)", tx, s_i, base_w_i);

    size_t a = mem->align;
    shared_mem_segment seg = mem->segments[s_i];
    for (size_t offset = 0; offset < size / a; offset++)
    {
        size_t w_i = base_w_i + offset;

        if ( !transaction->read_only )
        {
            lock_acquire(mem->modif_read.lock);
            mem->modif_read.segment_indices[mem->modif_read.size] = s_i;
            mem->modif_read.word_indices[mem->modif_read.size++] = w_i;
            lock_release(mem->modif_read.lock);
        }

        if ( !read_word(seg, w_i, target + offset * a, transaction, a) )
        {
            log_fatal(" [%p] read failed", tx);
            word_print(transaction, seg, w_i);
            leave_and_commit(mem, transaction);
            return false;
        }
    }

    return true;
}


bool write_word(shared_mem_segment seg, size_t w_i, const void* src, transaction_t* tx, size_t word_size)
{
    if ( as_write_op(&seg.access_sets[w_i], tx) )
    {
        memcpy(seg.writeCopies[w_i], src, word_size);
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

    size_t s_i = get_segment_index(target);
    size_t base_w_i = get_word_index(target); 

    // log_info(" [%p]  tm_write  target=(%zu, %zu), size: %zu", tx, s_i, base_w_i, size);

    size_t a = mem->align;
    shared_mem_segment seg = mem->segments[s_i];
    for (size_t offset = 0; offset < size / a; offset++)
    {
        size_t w_i = base_w_i + offset;

        lock_acquire(mem->modif_write.lock);
        mem->modif_write.segment_indices[mem->modif_write.size] = s_i;
        mem->modif_write.word_indices[mem->modif_write.size++] = w_i;
        lock_release(mem->modif_write.lock);

        if ( !write_word(seg, w_i, source + offset * a, transaction, a) ) 
        {
            // TODO: problem when writeV, writeX
            // undo writeV?
            // set word to invalid?
            log_fatal(" [%p] write failed", tx);
            word_print(transaction, seg, w_i);
            leave_and_commit(mem, transaction);
            return false;
        }
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
    log_debug(" [%p]  tm_alloc  start", tx);
    shared_mem* mem = (shared_mem*) shared;
    transaction_t* transaction = (transaction_t*) tx;

    if ( segment_alloc(mem, size) )
    {
        batcher_leave(mem->batcher, transaction);
        return nomem_alloc;
    }

    *target = SEG_ADDR(mem->allocated_segments);

    log_debug(" [%p]  tm_alloc  end, target=%p", tx, *target);

    return success_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t tx, void* target) {
    log_debug("[%p]  tm_free  start target=%p", tx, target);

    // TODO: retrieve segment from target?
    shared_mem_segment* segment = (shared_mem_segment*) target;
    transaction_t* ts = (transaction_t*) tx;

    ts->seg_free[ts->seg_free_size++] = segment;

    log_debug("tm_free end\n");
    return true;
}
