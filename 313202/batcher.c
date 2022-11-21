#include <stdlib.h>
#include <stdatomic.h>

#include "macros.h"
#include "batcher.h"
#include "lock.h"
#include "vec.h"
#include "logger.h"

batcher* get_batcher()
{
    batcher* b = malloc(sizeof(batcher)); 
    if ( unlikely( b == NULL ) ) return NULL;

    b->counter = 0;
    b->remaining = 0;

    b->blocked = vector_create();
    if ( unlikely( b->blocked == NULL ) )
    {
        free(b);
        return NULL;
    }

    b->lock = malloc(sizeof(struct lock_t));
    if ( unlikely( !lock_init(b->lock) ) )
    {
        lock_cleanup(b->lock);
        free(b->blocked);
        free(b);
        return NULL;
    }
    
    return b;
}

//TODO: why?
size_t batcher_epoch(batcher* batch)
{
    return atomic_load(&batch->counter);
}

void batcher_enter(batcher* b)
{
    // TODO: thread[] to tx[]
    // TODO: if counter == 0, let everyone in
    size_t zero = 0;
    bool first = atomic_compare_exchange_strong(&b->remaining, &zero, 1);
    log_info("  batch_enter  first=%u, thread=%zu", first, pthread_self());
    if ( !first )
    {
        // TODO: atomic array
        vector_add(&b->blocked, pthread_self());
        lock_acquire(b->lock);
        lock_wait(b->lock);
    }
    log_info("  batch_enter  - end  first=%u, thread=%zu", first, pthread_self());
}

/**
 * @brief returns true if last tx to leave 
 */
bool batcher_leave(batcher* b)
{
    size_t one = 1;
    size_t nb_blocked = vector_size(b->blocked);
    bool none_remaining = atomic_compare_exchange_strong(&b->remaining, &one, nb_blocked);
    log_info("  batch_leave  none_remaining=%u", none_remaining);

    if ( none_remaining )
    {
        atomic_fetch_add(&b->counter, 1);
        lock_release(b->lock);
        lock_wake_up(b->lock); 
        for (size_t i = 0; i < nb_blocked; i++)
            vector_remove(&b->remaining, i);
    }
    return none_remaining;
}

void batcher_free(batcher* b)
{
    lock_cleanup(b->lock);
    vector_free(b->blocked);
    b->blocked = NULL;
    free(b);
}