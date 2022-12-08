#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "tm.h"
#include "logger.h"

#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

/** Define a proposition as likely true.
 * @param prop Proposition
**/
#undef likely
#ifdef __GNUC__
    #define likely(prop) \
        __builtin_expect((prop) ? true : false, true /* likely */)
#else
    #define likely(prop) \
        (prop)
#endif

/** Define a proposition as likely false.
 * @param prop Proposition
**/
#undef unlikely
#ifdef __GNUC__
    #define unlikely(prop) \
        __builtin_expect((prop) ? true : false, false /* unlikely */)
#else
    #define unlikely(prop) \
        (prop)
#endif

/** Define a variable as unused.
**/
#undef unused
#ifdef __GNUC__
    #define unused(variable) \
        variable __attribute__((unused))
#else
    #define unused(variable)
    #warning This compiler has no support for GCC attributes
#endif

#define INIT_STATE 0
#define READ_STATE 1
#define DOUBLE_READ_STATE 2
#define WRITE_STATE 3
#define INVALID_STATE 4
    
#define SHIFT 8
#define STATE_MASK 0xFF

#define as_format(tx, as) ( (((size_t) tx) << SHIFT) | as )
#define as_extract_tx(as) ( (size_t) as >> SHIFT )
#define as_extract_state(as) ( ((size_t) as) & STATE_MASK ) 

#define load_tx(as) ((size_t) as_extract_tx( atomic_load(as) ))
#define load_state(as) ((char) as_extract_state( atomic_load(as) ))

#define WORD_POWER 48
#define SEG_ADDR(l) (void*) ((long long) l << WORD_POWER)
#define SEG_INDEX(addr) (((uintptr_t) addr) >> WORD_POWER) - 1
#define WORD_INDEX(addr) (((uintptr_t) addr) & 0xFFFFFFFFFFFF) >> 3 // TODO: diviser par mem_align


#define MAX_SEGMENTS (2 << 16)
#define MAX_WORDS (2 << 48)
#define MAX_MODIFIED_PER_EPOCH (2 << 20) // 13
#define MAX_MODIFIED_PER_TX (2 << 17) // 9
#define MAX_FREE_SEG (2 << 5)

typedef struct shared_mem shared_mem;
typedef struct shared_mem_segment shared_mem_segment;
typedef struct transaction_t transaction_t;
typedef struct batcher batcher;
typedef atomic_size_t access_set_t;

struct lock_t {
    pthread_mutex_t mutex;
    pthread_cond_t cv;
};

struct batcher
{
    bool blocked;
    size_t remaining;
    struct lock_t* block;
};

struct transaction_t
{
    bool read_only;

    size_t write_size;
    // to vec
    size_t write_words_indices[MAX_MODIFIED_PER_TX];

    size_t seg_free_size;
    // to vec
    shared_mem_segment* seg_free[MAX_FREE_SEG];
};

struct shared_mem_segment
{
    size_t size;
    bool free;

    access_set_t* access_sets;
    void* readCopies; 
    void* writeCopies;
};

struct modified_words_lock
{
    size_t segment_indices[MAX_MODIFIED_PER_EPOCH];
    size_t word_indices[MAX_MODIFIED_PER_EPOCH];
    size_t size;
    struct lock_t* lock;
};


struct shared_mem
{
    size_t align;

    batcher* batcher;

    struct modified_words_lock modif_read; 
    struct modified_words_lock modif_write;

    atomic_int allocated_segments;
    shared_mem_segment segments[MAX_SEGMENTS];
};

static void as_revert_write(access_set_t* as, transaction_t* tx);
static char as_read_op(access_set_t* as, transaction_t* tx);
static bool as_write_op(access_set_t* as, transaction_t* tx);
static void as_reset(access_set_t* as);

static batcher* get_batcher();
static void batcher_enter(batcher* b, transaction_t* tx);
static void batcher_free(batcher* b);
static void batcher_wake_up(batcher* b);
static bool batcher_leave(batcher* b, transaction_t* tx);
static void batcher_block_entry(batcher* b);

static bool lock_init(struct lock_t* lock);
static void lock_cleanup(struct lock_t* lock);
static bool lock_acquire(struct lock_t* lock);
static void lock_release(struct lock_t* lock);
static void lock_wait(struct lock_t* lock);
static void lock_wake_up(struct lock_t* lock);

static bool segment_alloc(shared_mem* mem, size_t size);
static size_t get_segment_index( void const* addr );
static size_t get_word_index( void const* addr );
static void segment_free(shared_mem_segment* seg);

static tx_t transaction_init(shared_mem* mem, bool is_ro);
static void transaction_register_write_word(transaction_t* tx, size_t idx);
static void transaction_abort(shared_mem* mem, transaction_t* tx);

static void commit( shared_mem* mem, transaction_t* tx );
static bool leave_and_commit(shared_mem* mem, transaction_t* tx);
static bool read_word(shared_mem_segment seg, size_t w_i, void* read_to, transaction_t* tx, size_t align);
static bool read_word_main(shared_mem* mem, void* target, size_t s_i, size_t w_i, transaction_t* tx, size_t a);
static bool write_word(shared_mem_segment seg, size_t w_i, void const* src, transaction_t* tx, size_t align);
static bool write_word_main(shared_mem* mem, void const* source, size_t s_i, size_t w_i, transaction_t* tx, size_t a);

static size_t word_save_read_modif(shared_mem* mem, size_t s_i, size_t w_i);
static size_t word_save_write_modif(shared_mem* mem, size_t s_i, size_t w_i);

size_t format( void* src, size_t size )
{
    size_t f = 0;
    memcpy(&f, src, size);
    return f;
}

size_t word_print(shared_mem* mem, transaction_t* tx, shared_mem_segment seg, size_t w_i)
{
    size_t s = atomic_load(&seg.access_sets[w_i]);
    void* read = seg.readCopies + w_i * mem->align;
    void* write = seg.writeCopies + w_i * mem->align;

    log_debug(
        "[%p] w_i=%zu, readCopy=(%p, %zu), writeCopy=(%p, %zu), access=(%zu, %p)", 
        tx, w_i,
        read, format(read, mem->align),
        write, format(write, mem->align),
        as_extract_state(s), as_extract_tx(s)
    );
    return format(read, mem->align);
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
    log_debug("=====================================");
}

static void as_revert_write(access_set_t* as, transaction_t* tx)
{
    // log_fatal("[%p] reverting word", tx);
    // 3 -> 0,  3 -> 1 -> 0
    size_t init_state = INIT_STATE; 
    size_t write_same_tx = as_format(tx, WRITE_STATE); 
    atomic_compare_exchange_strong(as, &write_same_tx, init_state);
}

static char as_read_op(access_set_t* as, transaction_t* tx)
{
    size_t init_state = INIT_STATE; 
    size_t read_same_tx = as_format(tx, READ_STATE); 
    size_t write_same_tx = as_format(tx, WRITE_STATE);

    // 0 -> 1 (init, _) -> (read, tx)
    if ( atomic_compare_exchange_strong(as, &init_state, read_same_tx) )
        return READ_STATE;

    // 1 -> 1 (read, tx) -> (read, tx)
    else if ( atomic_load(as) == read_same_tx )
        return READ_STATE;

    // 2 -> 2
    else if ( load_state(as) == DOUBLE_READ_STATE )
        return DOUBLE_READ_STATE;

    // 1 -> 2 (read, tx) -> (d_read, tx")
    size_t set = atomic_load(as);
    if ( 
        as_extract_state(set) == READ_STATE && 
        as_extract_tx(set) != ((size_t) tx) &&
        atomic_compare_exchange_strong(as, &set, as_format(tx, DOUBLE_READ_STATE)) 
    )
        return DOUBLE_READ_STATE;

    // 3 -> 3 (write, tx) -> (write, tx)
    else if ( set == write_same_tx )
        return WRITE_STATE;

    // read not allowed - pretend to be in invalid state
    return INVALID_STATE;
}

static bool as_write_op(access_set_t* as, transaction_t* tx)
{
    size_t init_state = INIT_STATE; 
    size_t write_same_tx = as_format(tx, WRITE_STATE); 
    size_t from_read_state_tx = as_format(tx, READ_STATE);

    // 0 -> 3 (init, _) -> (write, tx)
    if ( atomic_compare_exchange_strong(as, &init_state, write_same_tx) )
        return true;

    // 3 -> 3 (write, tx) -> (write, tx)
    else if ( atomic_load(as) == write_same_tx )
        return true;

    // 1 -> 3 (read, tx) -> (write, tx)
    else if ( atomic_compare_exchange_strong(as, &from_read_state_tx, write_same_tx) )
        return true;
    
    // (write, tx") write not allowed 
    return false;
}

static void as_reset(access_set_t* as)
{
    atomic_store(as, INIT_STATE);
}

static batcher* get_batcher()
{
    batcher* b = malloc(sizeof(batcher)); 
    if ( unlikely( b == NULL ) ) 
        return NULL;

    b->blocked = false;
    b->remaining = 0;

    // TODO: need for malloc?
    b->block = malloc(sizeof(struct lock_t));
    if (unlikely( b->block == NULL || !lock_init(b->block) ))
    {
        free(b);
        return NULL;
    }

    return b;
}

static void batcher_enter(batcher* b, transaction_t* tx)
{
    lock_acquire(b->block);
    while ( b->blocked )
        lock_wait(b->block);

    b->remaining++;
    log_info("[%p] batch_enter  blocked=%u, remaining=%zu", tx, b->blocked, b->remaining);
    lock_release(b->block);
}

/**
 * TODO - grader: modify policy
 * Policy: block on read_only finished
 *  OR last one to leave
 */
static void batcher_block_entry(batcher* b)
{
    b->blocked = true;
}

static bool batcher_leave(batcher* b, transaction_t* tx)
{
    lock_acquire(b->block);

    bool last = --b->remaining == 0;
    log_debug("[%p] batcher_leave remaining=%zu", tx, b->remaining);
    if ( tx->read_only )
        batcher_block_entry(b);

    return last;
}

static void batcher_wake_up(batcher* b)
{
    b->blocked = false;
    lock_release(b->block);
    lock_wake_up(b->block);
}

static void batcher_free(batcher* b)
{
    if (likely( b->block != NULL ))
    {
        lock_cleanup(b->block);
        free(b->block);
    }
    free(b);
}

static bool lock_init(struct lock_t* lock) {
    return pthread_mutex_init(&(lock->mutex), NULL) == 0
        && pthread_cond_init(&(lock->cv), NULL) == 0;
}

static void lock_cleanup(struct lock_t* lock) {
    pthread_mutex_destroy(&(lock->mutex));
    pthread_cond_destroy(&(lock->cv));
}

static bool lock_acquire(struct lock_t* lock) {
    return pthread_mutex_lock(&(lock->mutex)) == 0;
}

static void lock_release(struct lock_t* lock) {
    pthread_mutex_unlock(&(lock->mutex));
}

static void lock_wait(struct lock_t* lock) {
    pthread_cond_wait(&(lock->cv), &(lock->mutex));
}

static void lock_wake_up(struct lock_t* lock) {
    pthread_cond_broadcast(&(lock->cv));
}

static bool segment_alloc(shared_mem* mem, size_t size)
{
    shared_mem_segment seg; 

    seg.size = size;
    seg.free = false;
    seg.access_sets = calloc(size, sizeof(access_set_t)); 
    seg.writeCopies = calloc(size, mem->align);  
    seg.readCopies = calloc(size, mem->align);
    
    if ( unlikely( 
        seg.access_sets == NULL || 
        seg.writeCopies == NULL || 
        seg.readCopies == NULL 
    ) )
    {
        free(seg.access_sets);
        free(seg.writeCopies);
        free(seg.readCopies);
        return true;
    }

    mem->segments[mem->allocated_segments++] = seg;

    return false;
}

static size_t get_segment_index( void const* addr )
{
    return (size_t) SEG_INDEX((uintptr_t) addr);
}


static size_t get_word_index( void const* addr )
{
    return (size_t) WORD_INDEX((uintptr_t) addr);
}

static void segment_free(shared_mem_segment* seg)
{
    free(seg->access_sets);
    free(seg->writeCopies);
    free(seg->readCopies);
    seg->free = true;
}

static void abort_fail(shared_mem* mem, transaction_t* tx)
{
    // TODO: free the allocated segments
    transaction_abort(mem, tx);
    leave_and_commit(mem, tx);
    // free(tx);
}

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) 
{
    // log_set_quiet(true);

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

static void commit( shared_mem* mem, transaction_t* tx )
{
    lock_acquire(mem->modif_write.lock);
    log_debug("/////// Committting ////////");

    size_t ws = mem->modif_write.size;
    size_t a = mem->align;
    for (size_t i = 0; i < ws; i++)
    {
        size_t s_i = mem->modif_write.segment_indices[i];
        size_t w_i = mem->modif_write.word_indices[i];
        shared_mem_segment seg = mem->segments[s_i];

        word_print(mem, tx, seg, w_i);
        if ( load_state(seg.access_sets + w_i) == WRITE_STATE )
        {
            log_fatal("swapping ");
            memcpy(seg.readCopies + w_i * a, seg.writeCopies + w_i * a, a);
        }

        as_reset(seg.access_sets + w_i);
        word_print(mem, tx, seg, w_i);
    }
    mem->modif_write.size = 0;
    lock_release(mem->modif_write.lock); 

    // reset access set of read words
    lock_acquire(mem->modif_read.lock);
    size_t rs = mem->modif_read.size;
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
static bool leave_and_commit(shared_mem* mem, transaction_t* tx)
{
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
    shared_mem* mem = (shared_mem*) shared;
    transaction_t* ts = (transaction_t*) tx;

    bool committed = leave_and_commit(mem, ts);

    // free the segments
    size_t s = ts->seg_free_size;
    for (size_t i = 0; i < s; i++)
    {
        segment_free(ts->seg_free[i]);
    }
    ts->seg_free_size = 0;   

    free(ts);
    return committed;
}

static bool read_word(shared_mem_segment seg, size_t w_i, void* read_to, transaction_t* tx, size_t align)
{
    // if ( tx->read_only )
    //     memcpy(read_to, seg.readCopies + w_i * align, align);
    // else
    // {
    char state = as_read_op(seg.access_sets + w_i, tx);
    if ( state == INVALID_STATE )
        return true;
    else if ( state == WRITE_STATE )
        memcpy(read_to, seg.writeCopies + w_i * align, align);
    else if ( state == READ_STATE || state == DOUBLE_READ_STATE )
        memcpy(read_to, seg.readCopies + w_i * align, align);
    // }

    return false;
}

static bool read_word_main(shared_mem* mem, void* target, size_t s_i, size_t w_i, transaction_t* tx, size_t a)
{
    shared_mem_segment seg = mem->segments[s_i];

    if ( read_word(seg, w_i, target, tx, a) )
    {
        log_fatal(" [%p] read failed", tx, s_i, w_i);
        abort_fail(mem, tx);
        return true;
    }

    word_print(mem, tx, seg, w_i);
    word_save_read_modif(mem, s_i, w_i);
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
    size_t a = mem->align;

    log_info("[%p] tm_read  start, (%zu, %zu)", tx, s_i, base_w_i);

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


static bool write_word(shared_mem_segment seg, size_t w_i, void const* src, transaction_t* tx, size_t align)
{
    if ( as_write_op(seg.access_sets + w_i, tx) )
    {
        memcpy(seg.writeCopies + w_i * align, src, align);
        return false;
    }

    return true;
}

static bool write_word_main(shared_mem* mem, void const* source, size_t s_i, size_t w_i, transaction_t* tx, size_t a)
{
    shared_mem_segment seg = mem->segments[s_i];

    if ( write_word(seg, w_i, source, tx, a) ) 
    {
        log_fatal(" [%p] write failed (%zu, %zu)", tx, s_i, w_i);
        // word_print(mem, transaction, seg, w_i);
        abort_fail(mem, tx);
        return true;
    }

    word_print(mem, tx, seg, w_i);

    size_t idx = word_save_write_modif(mem, s_i, w_i);
    transaction_register_write_word(tx, idx);
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
    size_t a = mem->align;

    log_error("[%p] tm_write  target=(%zu, %zu), writing=%zu, size: %zu", tx, s_i, base_w_i, *((size_t*)(source)), size);

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
    shared_mem_segment* segment = (shared_mem_segment*) target;
    transaction_t* ts = (transaction_t*) tx;
    ts->seg_free[ts->seg_free_size++] = segment;
    return true;
}


static tx_t transaction_init(shared_mem* mem, bool is_ro)
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

static void transaction_register_write_word(transaction_t* tx, size_t idx)
{
    tx->write_words_indices[tx->write_size++] = idx;
}

static void transaction_abort(shared_mem* mem, transaction_t* tx)
{
    // TODO: free allocated segments
  
    // TODO: don't care if very slow 
    // if more than 2>>16 alloc -> find free segments

    size_t* w = tx->write_words_indices;
    size_t s = tx->write_size;
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

static size_t word_save_read_modif(shared_mem* mem, size_t s_i, size_t w_i)
{
    lock_acquire(mem->modif_read.lock);
    size_t idx = mem->modif_read.size;
    mem->modif_read.segment_indices[idx] = s_i;
    mem->modif_read.word_indices[idx] = w_i;
    mem->modif_read.size++;
    lock_release(mem->modif_read.lock);
    return idx;
}

static size_t word_save_write_modif(shared_mem* mem, size_t s_i, size_t w_i)
{
    lock_acquire(mem->modif_write.lock);
    size_t idx = mem->modif_write.size;
    mem->modif_write.segment_indices[idx] = s_i;
    mem->modif_write.word_indices[idx] = w_i;
    mem->modif_write.size++;
    lock_release(mem->modif_write.lock);
    return idx;
}