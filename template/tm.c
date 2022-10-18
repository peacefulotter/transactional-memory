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

// Internal headers
#include <tm.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "macros.h"
#include "access_set.h"
#include "word.h"


// We allocate the shared memory buffer such that its words are correctly aligned.
// if (posix_memalign(&mem, align, size) != 0) {
//     free(mem);
//     return invalid_shared;
// }


/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) {
    shared_mem* mem = malloc(sizeof(shared_mem));
    if ( unlikely(mem == NULL) ) 
        return invalid_shared;

    mem->segments_nb = 0;
    mem->segments = malloc(sizeof(shared_mem_segment*)); // TODO: int posix_memalign(void **memptr, size_t alignment, size_t size);
    if ( mem->segments == NULL )
    {
        free(mem);
        return invalid_shared;
    }

    mem->align = align;
    mem->size = size;
    return mem;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t unused(shared)) {
    // TODO: tm_destroy(shared_t)
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared) {
    if ( shared == NULL ) return NULL;
    return ((shared_mem*) shared)->segments;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) {
    if ( shared == NULL ) return NULL;
    return ((shared_mem*) shared)->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) {
    if ( shared == NULL ) return NULL;
    return ((shared_mem*) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) {
    // TODO: shared for what?
    transaction* tx = malloc(sizeof(transaction*));
    if ( tx == NULL ) 
        return invalid_tx;
    tx->id = 0; // TODO id?
    tx->read_only = is_ro;
    return tx;
}


bool commit( shared_mem* mem )
{
    // foreach written word index do
    //          TODO: question: <defer the swap??>, of which copy for word index is the “valid”
    //          copy, just after the last transaction from the current epoch
    //          leaves the Batcher and before the next batch starts running;
    //      end
    for (size_t i = 0; i < mem->segments_nb; i++)
    {
        shared_mem_segment* segment = mem->segments[i];
        shared_mem_word* words = segment->words;
        for (size_t j = 0; j < segment->nb_words; j++)
        {
            words[j].ctrl_valid;
        }
    }
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) {
    shared_mem* mem = (shared_mem*) shared;
    
    batcher* b = mem->segments[0]->batcher;
    // batcher_leave(b)
    if ( b->remaining == 0 ) 
        commit(mem);

    return true;
}

bool read_word(shared_mem_word* word, void* read_to, transaction* tx, size_t word_size)
{
    shared_mem_word w = *word;

    if ( tx->read_only )
    {
        memcpy(read_to, word->readCopy, word_size);
        return true;
    }
    else if ( word->ctrl_written )
    {
        if ( as_contains( word->ctrl_access_set, tx ) )
        {
            memcpy(read_to, word->writeCopy, word_size);
            return true;
        }
        else
            return false;
    }
    else
    {
        memcpy(read_to, word->readCopy, word_size);
        if ( !as_contains(word->ctrl_access_set, tx ) )
            add( word->ctrl_access_set, tx );
        return true;
    }
}

bool write_word(shared_mem_word* word, void* write_to, tx_t tx, size_t word_size)
{
    shared_mem_word w = *word;
    if ( w.ctrl_written )
    {
        if ( as_contains(w.ctrl_access_set, tx) )
        {
            memcpy(write_to, w.writeCopy, word_size);
            return true;
        }
        else
            return false;
    }
    else
    {
        if ( w.ctrl_nb_accessed > 0 )
            return false;
        else
        {
            memcpy(write_to, w.writeCopy, word_size);
            if ( !as_contains(w.ctrl_access_set, tx) )
                add(w.ctrl_access_set, tx);
            w.ctrl_written = true;
            return true;
        }
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
    shared_mem* mem = (shared_mem*) shared;
    shared_mem_word* word = (shared_mem_segment*) source;

    size_t word_size = mem->align;
    
    for (size_t offset = 0; offset < size; offset += word_size)
    {
        bool result = read_word(word + offset, target + offset, tx, word_size);
        if ( !result )
            return false;
    }
    return true;
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
    shared_mem_word* word = (shared_mem_segment*) target;

    size_t word_size = mem->align;
    
    for (size_t offset = 0; offset < size; offset  += word_size)
    {
        bool result = write_word(word + offset, source + offset, tx, word_size);
        if ( !result )
            return false;
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
// FIXME - QUESTION: unused tx?
alloc_t tm_alloc(shared_t shared, tx_t unused(tx), size_t size, void** target) {
    shared_mem* mem = (shared_mem*) shared;
    size_t word_size = mem->align;
    size_t nb_words = size / word_size;

    // allocate new mem segment
    shared_mem_segment* segment = malloc(sizeof(shared_mem_segment*));
    if ( segment ==  NULL )
        return nomem_alloc;
    
    // initialize segment
    segment->batcher; // TODO: init batcher
    segment->nb_words = nb_words;
    segment->words = calloc(segment->nb_words, word_size);

    // initialize each word
    for (size_t i = 0; i < nb_words; i++)
    {
        shared_mem_word* word = initialize_word(); // FIXME: size of alignment
        if ( word == NULL )
        {
            // TODO: free all prior
        }
        segment->words[i] = *word;
    }

    *target = segment;
    mem->segments[mem->segments_nb] = segment;

    // allocate new mem segment pointer
    mem->segments = realloc(mem->segments, (mem->segments_nb + 1) * sizeof(shared_mem_segment*));
    if ( mem->segments == NULL )
        return nomem_alloc;

    mem->segments_nb++;

    return success_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(target)) {
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
