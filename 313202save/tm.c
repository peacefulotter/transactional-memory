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
#include "mem.h"
#include "macros.h"
#include "word.h"
#include "batcher.h"
#include "vec.h"
#include "segment.h"
#include "logger.h"
#include "virtual.h"
#include "access_set.h"
#include "transaction.h"

bool leave_and_commit(shared_mem* mem, transaction_t* tx);
bool read_word(shared_mem_segment seg, size_t w_i, void* read_to, transaction_t* tx, size_t word_size);
bool write_word(shared_mem_segment seg, size_t w_i, void const* write_from, transaction_t* tx, size_t word_size);


void abort_fail(shared_mem* mem, transaction_t* tx)
{
    // TODO: free the allocated segments
    // log_fatal("[%p] abort_fail", tx);
    tx_abort(mem, tx);
    leave_and_commit(mem, tx);
    // free(tx);
}

void print_mem(shared_mem* mem, transaction_t* tx)
{ 
    log_debug("=====================================");
    log_debug("mem.align: %zu", mem->align);
    size_t s = atomic_load(&mem->allocated_segments);
    log_debug("mem.allocated_segments: %zu", s);
    for (size_t i = 0; i < s; i++)
    {
        shared_mem_segment s = mem->segments[i];
        log_debug("segment nb %zu, segment size: %zu", i, s.size);
        size_t sum = 0;
        size_t count = 0;
        for (size_t j = 0; j < 10; j++)
        {
            size_t v = word_print(mem, tx, s, j);
            if (j > 0 && v > 0)
            {
                sum += v;
                count++;
            }
        }
        log_debug("[%p] Sum: %zu, count: %zu, average: %f", tx, sum, count, (float) sum / (float) count);
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
shared_t tm_create(size_t size, size_t align) 
{
    log_set_quiet(true);

    log_info("===== tm_create start size: %zu, align: %zu", size, align);
    shared_mem* mem = malloc(sizeof(shared_mem));
    if ( unlikely(mem == NULL) ) 
        return invalid_shared;

    mem->align = align;
    mem->allocated_segments = 0;

    mem->batcher = get_batcher();
    if ( mem->batcher == NULL )
        goto fail_tm_create;

    if ( segment_alloc(mem, size) )
        goto fail_tm_create;

    mem->modif_read.size = 0;
    mem->modif_write.size = 0;

    mem->modif_read.lock = malloc(sizeof(struct lock_t));
    if ( unlikely( mem->modif_read.lock == NULL || !lock_init(mem->modif_read.lock) ) )
        goto fail_tm_create;

    mem->modif_write.lock = malloc(sizeof(struct lock_t));
    if ( unlikely( mem->modif_write.lock == NULL || !lock_init(mem->modif_write.lock) ) )
        goto fail_tm_write_lock;

    print_mem(mem, NULL);

    return mem;

fail_tm_write_lock: 
    lock_cleanup(mem->modif_read.lock);
    free(mem->modif_read.lock);
fail_tm_create:
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
        segment_free(mem->segments + i);

    lock_cleanup(mem->modif_read.lock);
    lock_cleanup(mem->modif_write.lock);
    free(mem->modif_read.lock);
    free(mem->modif_write.lock);
    
    mem->allocated_segments = 0;
    mem->align = 0;

    free(mem);

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
    return transaction_init(mem, is_ro);
}

bool swap(void *a, void *b, size_t width)
{
    memcpy(a, b, width);
    return false;
}


void commit( shared_mem* mem, transaction_t* tx )
{
    // swap written words
    lock_acquire(mem->modif_write.lock);
    size_t ws = mem->modif_write.size;
    mem->max_write = ws > mem->max_write ? ws : mem->max_write;
    // printf("mem -> MAX WRITE SIZE: %zu \n", mem->max_write);

    log_info("[%p]  commit  start, mem written word=%zu", tx, ws);
    for (size_t i = 0; i < ws; i++)
    {
        size_t s_i = mem->modif_write.segment_indices[i];
        size_t w_i = mem->modif_write.word_indices[i];
        shared_mem_segment seg = mem->segments[s_i];

        if ( ws > MAX_MODIFIED_PER_EPOCH - 3 )
        {
            printf("w SIZE=%zu, seg_i=%zu, word_i=%zu\n", ws, s_i, w_i);
            word_print(mem, tx, seg, w_i);
        }

        if ( load_state(seg.access_sets + w_i) == WRITE_STATE )
        {
            size_t a = mem->align;
            swap(seg.readCopies + w_i * a, seg.writeCopies + w_i * a, a);
        }

        as_reset(seg.access_sets + w_i);
    }
    mem->modif_write.size = 0;
    lock_release(mem->modif_write.lock); 

    // reset access set of read words
    lock_acquire(mem->modif_read.lock);
    size_t rs = mem->modif_read.size;
    mem->max_read = rs > mem->max_read ? rs : mem->max_read;
    // printf("mem -> MAX READ SIZE: %zu \n", mem->max_read);
    for (size_t i = 0; i < rs; i++)
    {
        size_t s_i = mem->modif_read.segment_indices[i];
        size_t w_i = mem->modif_read.word_indices[i];
        shared_mem_segment seg = mem->segments[s_i];
        as_reset(seg.access_sets + w_i);
    }
    mem->modif_read.size = 0;
    lock_release(mem->modif_read.lock);
}


// leave batcher - no more threads remaining => commit
// returns true if commited succesfully or not allow to commit (not last tx on batcher)
bool leave_and_commit(shared_mem* mem, transaction_t* tx)
{
    // log_warn("[%p]  leave_and_commit start", tx);

    batcher* b = mem->batcher;

    if ( batcher_leave(b, tx) ) 
    {
        commit(mem, tx);
        print_mem(mem, tx);
        batcher_wake_up(b);
    }
    else
        lock_release(b->block);

    return true;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) {
   // log_info("[%p]  tm_end  start", tx);

    shared_mem* mem = (shared_mem*) shared;
    transaction_t* ts = (transaction_t*) tx;

    bool committed = leave_and_commit(mem, ts);

    // free the segments
    size_t s = ts->seg_free_size;
    for (size_t i = 0; i < s; i++)
    {
        log_fatal("[%p] Freeing segment: %zu", tx, i);
        segment_free(ts->seg_free[i]);
    }
    ts->seg_free_size = 0;   

    free(ts);

    // log_info("[%p]  tm_end  end, commited=%u", tx, committed);
    return committed;
}

bool read_word(shared_mem_segment seg, size_t w_i, void* read_to, transaction_t* tx, size_t align)
{
    if ( tx->read_only )
        memcpy(read_to, seg.readCopies + w_i * align, align);
    else
    {
        char state = as_read_op(seg.access_sets + w_i, tx);
        if ( state == INVALID_STATE )
            return false;
        else if ( state == WRITE_STATE )
            memcpy(read_to, seg.writeCopies + w_i * align, align);
        else if ( state == READ_STATE || state == DOUBLE_READ_STATE )
            memcpy(read_to, seg.readCopies + w_i * align, align);
    }

    return true;
}

bool read_word_main(shared_mem* mem, void* target, size_t s_i, size_t w_i, transaction_t* tx, size_t a)
{
    shared_mem_segment seg = mem->segments[s_i];

    if ( !read_word(seg, w_i, target, tx, a) )
    {
        // log_fatal(" [%p] read failed", tx, s_i, w_i);
        abort_fail(mem, tx);
        return true;
    }

    word_save_read_modif(mem, s_i, w_i);
    // word_print(mem, tx, seg, w_i);
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
    transaction_t* ts = (transaction_t*) tx;

    size_t s_i = get_segment_index(source);
    size_t base_w_i = get_word_index(source);

    // log_info(" [%p]  tm_read  start, (%zu, %zu)", tx, s_i, base_w_i);

    size_t a = mem->align;
    if ( unlikely( size > a ) )
    {
        for (size_t offset = 0; offset < size / a; offset++)
            if ( read_word_main(mem, target + offset * a, s_i, base_w_i + offset, ts, a) )
                return false;
    }
    else if ( read_word_main(mem, target, s_i, base_w_i, ts, a) )
        return false;

    return true;
}


bool write_word(shared_mem_segment seg, size_t w_i, void const* src, transaction_t* tx, size_t align)
{
    if ( as_write_op(seg.access_sets + w_i, tx) )
    {
        memcpy(seg.writeCopies + w_i * align, src, align);
        return true;
    }

    return false;
}

bool write_word_main(shared_mem* mem, void const* source, size_t s_i, size_t w_i, transaction_t* tx, size_t a)
{
    shared_mem_segment seg = mem->segments[s_i];

    if ( !write_word(seg, w_i, source, tx, a) ) 
    {
        // log_fatal(" [%p] write failed (%zu, %zu)", tx, s_i, w_i);
        // word_print(mem, transaction, seg, w_i);
        abort_fail(mem, tx);
        return true;
    }

    // word_print(mem, tx, seg, w_i);

    size_t idx = word_save_write_modif(mem, s_i, w_i);
    tx_register_write_word(tx, idx);
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
    transaction_t* ts = (transaction_t*) tx;

    size_t s_i = get_segment_index(target);
    size_t base_w_i = get_word_index(target); 

    // log_info(" [%p]  tm_write  target=(%zu, %zu), writing=%zu, size: %zu", tx, s_i, base_w_i, *((size_t*)(source)), size);

    size_t a = mem->align;

    if ( unlikely( size > a ) )
    {
        for (size_t offset = 0; offset < size / a; offset++)
            if ( write_word_main(mem, source + offset * a, s_i, base_w_i + offset, ts, a) )
                return false;
    }
    else if ( write_word_main(mem, source, s_i, base_w_i, ts, a) )
        return false;


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
    // log_debug(" [%p]  tm_alloc  start", tx);

    shared_mem* mem = (shared_mem*) shared;
    transaction_t* ts = (transaction_t*) tx;

    if ( segment_alloc(mem, size) )
    {
        abort_fail(mem, ts);
        return nomem_alloc;
    }

    *target = SEG_ADDR(mem->allocated_segments);

    // log_debug(" [%p] tm_alloc  end, target=%p", tx, *target);

    return success_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t tx, void* target) {
    log_debug("[%p]  tm_free  start target=%p \n", tx, target);

    shared_mem_segment* segment = (shared_mem_segment*) target;
    transaction_t* ts = (transaction_t*) tx;

    ts->seg_free[ts->seg_free_size++] = segment;

    log_debug("tm_free end\n");
    return true;
}
