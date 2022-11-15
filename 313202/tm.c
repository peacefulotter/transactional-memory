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

// TODO: compare and swap
// TODO: refactor access_set

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
            word_print(s.words[j]);
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
    log_info("===== tm_create start size: %zu, align: %zu", size, align);
    shared_mem* mem = malloc(sizeof(shared_mem));
    if ( unlikely(mem == NULL) ) 
        return invalid_shared;

    mem->align = align;
    // TODO: get_batcher might fail
    mem->batcher = get_batcher();
    mem->allocated_segments = 0;

    if ( segment_alloc(mem, size) )
    {
        batcher_release(mem->batcher);
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
    printf("tm_destroy start\n");
    shared_mem* mem = (shared_mem*) shared;
    
    mem->align = 0;
    mem->allocated_segments = 0;

    batcher_release(mem->batcher);

    size_t nb = atomic_load(&mem->allocated_segments);
    for (size_t i = 0; i < nb; i++)
        segment_free(mem->segments[i]);
    free(mem->segments);

    printf("tm_destroy end\n");
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared) {
    if ( shared == NULL ) return NULL;
    // ((shared_mem*) shared)->segments_vec
    return 1 << 48;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) {
    if ( shared == NULL ) return 0;
    return ((shared_mem*) shared)->segments[0].size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) {
    if ( shared == NULL ) return 0;
    return ((shared_mem*) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t unused(shared), bool is_ro) 
{
    transaction_t* tx = malloc(sizeof(transaction_t));
    if ( tx == NULL ) 
        return invalid_tx;
    tx->read_only = is_ro;
    tx->seg_free_vec = vector_create();
    tx->written_word_vec = vector_create();

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
    log_info("commit start");

    size_t s = vector_size(tx->written_word_vec);
    for (size_t i = 0; i < s; i++)
    {
        shared_mem_word* w = tx->written_word_vec[i];
        if ( !swap(w->readCopy, w->writeCopy, mem->align) )
            return false;
        atomic_store(&w->ctrl_written, false);
    }
    vector_free(tx->written_word_vec); 

    log_info("commit end");
    return true;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) {
    log_info("tm_end start");

    shared_mem* mem = (shared_mem*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    
    // leave batcher
    batcher* b = mem->batcher;
    batcher_leave(b);

    // no more transaction remaning => commit
    if ( b->remaining == 0 ) 
        commit(mem, transaction);

    // free the segments 
    size_t s = vector_size(transaction->seg_free_vec);
    for (size_t i = 0; i < s; i++)
        segment_free(*transaction->seg_free_vec[i]);
    vector_free(transaction->seg_free_vec);    

    log_info("tm_end end");
    return true;
}

bool read_word(shared_mem_word w, void* read_to, transaction_t* tx, size_t word_size)
{
    // log_info("[%p] read_word start (no end)", tx);
    // as_print(w.ctrl_access_set);
    // log_debug("[%p] contains?: %u", tx, as_contains(w.ctrl_access_set, tx));

    if ( tx->read_only )
    {
        memcpy(read_to, w.readCopy, word_size);
        return true;
    }
    else if ( w.ctrl_written )
    {
        if ( as_contains( w.ctrl_access_set, tx ) )
        {
            memcpy(read_to, w.writeCopy, word_size);
            return true;
        }
        else
            return false;
    }
    else
    {
        memcpy(read_to, w.readCopy, word_size);
        if ( !as_contains(w.ctrl_access_set, tx ) )
            as_add( w.ctrl_access_set, tx );
        return true;
    }
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
    // log_info("[%p] tm_read start", tx);
    shared_mem* mem = (shared_mem*) shared;
    transaction_t* transaction = (transaction_t*) tx;

    size_t seg_index = get_segment_index(source);
    size_t word_index = get_word_index(source);
    
    size_t a = mem->align;
    shared_mem_segment seg = mem->segments[seg_index];
    for (size_t offset = 0; offset < size / a; offset++)
    {
        if ( !read_word(seg.words[offset], target + offset * a, transaction, a) )
            return false;
    }
    // log_info("[%p] tm_read end", tx);
    return true;
}


bool write_word(shared_mem_word w, const void* write_from, transaction_t* tx, size_t word_size)
{
    log_info("[%p] write_word start (no end)", tx);
    log_debug("[%p] w.ctrl_written=%u", tx, w.ctrl_written);
    as_print(w.ctrl_access_set);
    log_debug("[%p] contains?: %u", tx, as_contains(w.ctrl_access_set, tx));
    
    if ( atomic_load(&w.ctrl_written) )
    {
        if ( as_contains(w.ctrl_access_set, tx) )
        {
            memcpy(w.writeCopy, write_from, word_size);
            return true;
        }
        else
            return false;
    }
    else
    {
        // TODO: purpose of if
        if ( vector_size(w.ctrl_access_set) > 0 )
            return false;
        else
        {
            memcpy(w.writeCopy, write_from, word_size);
            // TODO: no need to check for contains
            if ( !as_contains(w.ctrl_access_set, tx) )
                as_add(w.ctrl_access_set, tx);
            atomic_store(&w.ctrl_written, true);
            return true;
        }
    }
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

    size_t seg_index = get_segment_index(source);
    size_t word_index = get_word_index(source);
    
    log_info("[%p] tm_write start. source: %p, size: %zu", tx, source, size);

    size_t a = mem->align;
    shared_mem_segment seg = mem->segments[seg_index];
    for (size_t offset = 0; offset < size / a; offset++)
    {
        shared_mem_word word = seg.words[offset];
       log_debug("[%p] tm_write for, offset: %zu, writing: %zu", tx, offset, *((size_t*) source + offset));
        word_print(word);
        bool result = write_word(word, source + offset * a, transaction, a);
        word_print(word);
        if ( !result ) return false;
        vector_add(&transaction->written_word_vec, &word);
    }

    log_info("[%p] tm_write end", tx);
    return true;
}



/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t shared, tx_t unused(tx), size_t size, void** target) {
    printf("tm_alloc start\n");
    shared_mem* mem = (shared_mem*) shared;

    if ( segment_alloc(mem, size) )
        return nomem_alloc;

    *target = mem->allocated_segments << 48;

    printf("tm_alloc end, target=%p\n", *target);

    return success_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared, tx_t tx, void* target) {
    printf("tm_free start\n");

    shared_mem* mem = (shared_mem*) shared;
    shared_mem_segment* segment = (shared_mem_segment*) target;
    transaction_t* transaction = (transaction_t*) tx;

    vector_add(&transaction->seg_free_vec, segment);

    printf("tm_free end\n");
    return true;
}
