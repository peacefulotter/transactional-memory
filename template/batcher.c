#include "macros.h"
#include "batcher.h"
#include "lock.h"

batcher* get_batcher()
{
    batcher* b = calloc(1, sizeof(batcher)); 
    if ( unlikely( b == NULL ) ) return NULL;

    b->counter = 0;
    b->remaining = 0;
    b->nb_blocked = 0;
    b->blocked = calloc(MAX_BLOCKED, sizeof(pthread_t*));
    if ( unlikely( b->blocked == NULL ) )
    {
        free(b);
        return NULL;
    }

    b->lock = malloc(sizeof(struct lock_t));
    if ( unlikely( !lock_init(b->lock) ) )
    {
        lock_cleanup(b->lock);
        return NULL;
    }
    
    return b;
}

size_t batcher_epoch(batcher* batch)
{
    return batch->counter;
}

void batcher_enter(batcher* b)
{
    if ( b->remaining == 0 )
        b->remaining = 1;
    else
    {
        b->blocked[b->nb_blocked++] = pthread_self();
        lock_acquire(b->lock);
        lock_wait(b->lock);
        lock_release(b->lock);
    }
}

void batcher_leave(batcher* b)
{
    b->remaining--;
    if ( b->remaining == 0 )
    {
        b->counter++;
        b->remaining = b->nb_blocked;
        lock_wake_up(b->lock); 
        for ( size_t i = 0; i < b->nb_blocked; i++ )
        {
            b->blocked[i] = NULL;
        }
        b->nb_blocked = 0;
    }
}

void batcher_release(batcher* b)
{
    free(b->blocked);
    lock_cleanup(b->lock);
    free(b);
}