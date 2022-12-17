// TODO: not reloading
// TODO: fix mem leak of 88 bytes (? where is it coming from)
// 88 on single thread
// double free on concurrency

#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "tm.h"
#include "logger.h"
#include "vec.h"

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
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
#define BASE_TX_ID 1

#define SHIFT 8
#define STATE_MASK 0xFF

#define as_format(tx, as) (((tx->id) << SHIFT) | as)
#define as_extract_tx(as) ((size_t)as >> SHIFT)
#define as_extract_state(as) (((size_t)as) & STATE_MASK)

#define load_tx(as) ((size_t)as_extract_tx(atomic_load(as)))
#define load_state(as) ((char)as_extract_state(atomic_load(as)))

#define SEG_POWER 16
#define WORD_POWER 48
#define WORD_MASK 0xFFFFFFFFFFFF
#define TO_ADDR(s_i, w_i) (((s_i + 1) << WORD_POWER) | (w_i))
#define SEG_ADDR(l) ((void *)((long long)l << WORD_POWER))
#define SEG_INDEX(addr) ((((uintptr_t)addr) >> WORD_POWER) - 1)
#define WORD_INDEX(addr) (((uintptr_t)addr) & WORD_MASK)
#define WORD_INDEX_ALIGN(addr, align) (WORD_INDEX(addr) / align)

#define MAX_SEGMENTS (2 << SEG_POWER)
#define MAX_WORDS (2 << WORD_POWER)
#define MAX_MODIFIED_PER_EPOCH (2 << 10)

typedef struct shared_mem shared_mem;
typedef struct segment segment;
typedef struct transaction_t transaction_t;
typedef struct batcher batcher;
typedef atomic_size_t access_set_t;

struct lock_t
{
    pthread_mutex_t mutex;
    pthread_cond_t cv;
};

struct batcher
{
    bool blocked;
    bool first;
    size_t remaining;
    size_t tx_id;
    struct lock_t *block;
};

struct transaction_t
{
    size_t id;
    bool read_only;
    t_vec mod_words; // (s_i, w_i)
    t_vec free_segs;
    t_vec alloc_segs;
};

struct segment
{
    size_t size;
    int index;
    atomic_bool free;

    access_set_t *access_sets;
    void *readCopies;
    void *writeCopies;
};

struct modified_words_lock
{
    // TODO: get min, average, max
    t_vec indices; // size_t storing (seg_i, w_i);
    struct lock_t *lock;
};

struct shared_mem
{
    size_t align;

    batcher *batcher;

    struct modified_words_lock modif_read;
    struct modified_words_lock modif_write;

    t_vec seg_free;

    atomic_int allocated_segments;
    segment segments[MAX_SEGMENTS];
};

// Access set
static void as_revert(access_set_t *as, transaction_t *tx);
static char as_read_op(access_set_t *as, transaction_t *tx);
static bool as_write_op(access_set_t *as, transaction_t *tx);
static void as_reset(access_set_t *as);

// Batcher
static batcher *get_batcher();
static void batcher_enter(batcher *b, transaction_t *tx);
static void batcher_free(batcher *b);
static void batcher_wake_up(batcher *b);
static bool batcher_leave(batcher *b, transaction_t *tx, bool force_block);
static void batcher_block_entry(batcher *b);

// Lock
static bool lock_init(struct lock_t *lock);
static void lock_cleanup(struct lock_t *lock);
static bool lock_acquire(struct lock_t *lock);
static void lock_release(struct lock_t *lock);
static void lock_wait(struct lock_t *lock);
static void lock_wake_up(struct lock_t *lock);

// Segment
static bool segment_alloc(shared_mem *mem, size_t size);
static int get_segment_index(void const *addr);
static size_t get_word_index(void const *addr, size_t align);
static void segment_set_free(shared_mem *mem, int s_i);
static void segment_free(shared_mem *mem, int s_i);

// Transaction
static bool tx_mod_word(transaction_t *tx, void *addr);
static void tx_abort(shared_mem *mem, transaction_t *tx);
static void tx_free(transaction_t *tx);

static void commit(shared_mem *mem, transaction_t *tx);
static bool leave_and_commit(shared_mem *mem, transaction_t *tx, bool force_block);
static bool read_word(segment seg, size_t w_i, void *read_to, transaction_t *tx, size_t align);
static bool write_word(segment seg, size_t w_i, void const *src, transaction_t *tx, size_t align);

static bool word_save_read_modif(shared_mem *mem, void const *source);
static bool word_save_write_modif(shared_mem *mem, void *target);
static void word_print(shared_mem *mem, transaction_t *tx, int s_i, size_t w_i);

#define _word_print(mem, tx, s_i, w_i) ENABLE ? word_print(mem, tx, s_i, w_i) : NULL;

static size_t format(void *src, size_t size)
{
    size_t f = 0;
    memcpy(&f, src, size);
    return f;
}

static void word_print(shared_mem *mem, transaction_t *tx, int s_i, size_t w_i)
{
    segment seg = mem->segments[s_i];
    size_t s = atomic_load(&seg.access_sets[w_i]);
    void *read = seg.readCopies + w_i * mem->align;
    void *write = seg.writeCopies + w_i * mem->align;

    log_debug(
        "[%zu] (%u, %zu), read=(%p, %zu), write=(%p, %zu), access=(%zu, %zu)",
        tx->id, s_i, w_i,
        read, format(read, mem->align),
        write, format(write, mem->align),
        as_extract_state(s), as_extract_tx(s));
}

static size_t word_read_value(shared_mem *mem, segment seg, size_t w_i)
{
    void *read = seg.readCopies + w_i * mem->align;
    return format(read, mem->align);
}

static void print_mem(shared_mem *mem, transaction_t *tx)
{
    log_debug("=====================================");
    log_debug("mem.align: %zu", mem->align);
    size_t s = atomic_load(&mem->allocated_segments);
    log_debug("mem.allocated_segments: %zu", s);
    for (size_t i = 0; i < s; i++)
    {
        segment s = mem->segments[i];
        if ( atomic_load(&s.free) )
            continue;
        log_debug("segment nb %zu, segment size: %zu", i, s.size);
        size_t sum = 0;
        size_t count = 0;
        for (size_t j = 0; j < s.size; j++)
        {
            if (j <= 10)
                _word_print(mem, tx, i, j);
            size_t v = word_read_value(mem, s, j);
            if (j > 1 && v > 0)
            {
                sum += v;
                count++;
            }
        }
        log_debug("[%zu] Sum: %zu, count: %zu", tx->id, sum, count);
        log_debug("----------------------");
    }
    log_debug("=====================================");
}

static void as_revert(access_set_t *as, transaction_t *tx)
{
    // 3 -> 0,  3 -> 1 -> 0
    size_t write_same_tx = as_format(tx, WRITE_STATE);
    if (atomic_compare_exchange_strong(as, &write_same_tx, INIT_STATE))
        return;

    // 1 -> 0
    size_t read_same_tx = as_format(tx, READ_STATE);
    atomic_compare_exchange_strong(as, &read_same_tx, INIT_STATE);
}

static char as_read_op(access_set_t *as, transaction_t *tx)
{
    size_t init_state = INIT_STATE;
    size_t read_same_tx = as_format(tx, READ_STATE);
    size_t write_same_tx = as_format(tx, WRITE_STATE);

    // 0 -> 1 (init, _) -> (read, tx)
    if (atomic_compare_exchange_strong(as, &init_state, read_same_tx))
        return READ_STATE;

    // 1 -> 1 (read, tx) -> (read, tx)
    else if (atomic_load(as) == read_same_tx)
        return READ_STATE;

    // 2 -> 2
    else if (load_state(as) == DOUBLE_READ_STATE)
        return DOUBLE_READ_STATE;

    // 1 -> 2 (read, tx) -> (d_read, tx")
    size_t set = atomic_load(as);
    if (
        as_extract_state(set) == READ_STATE &&
        as_extract_tx(set) != tx->id &&
        atomic_compare_exchange_strong(as, &set, as_format(tx, DOUBLE_READ_STATE)))
        return DOUBLE_READ_STATE;

    // 3 -> 3 (write, tx) -> (write, tx)
    else if (set == write_same_tx)
        return WRITE_STATE;

    // read not allowed - pretend to be in invalid state
    return INVALID_STATE;
}

static bool as_write_op(access_set_t *as, transaction_t *tx)
{
    size_t init_state = INIT_STATE;
    size_t write_same_tx = as_format(tx, WRITE_STATE);
    size_t from_read_state_tx = as_format(tx, READ_STATE);

    // 0 -> 3 (init, _) -> (write, tx)
    if (atomic_compare_exchange_strong(as, &init_state, write_same_tx))
        return true;

    // 3 -> 3 (write, tx) -> (write, tx)
    else if (atomic_load(as) == write_same_tx)
        return true;

    // 1 -> 3 (read, tx) -> (write, tx)
    else if (atomic_compare_exchange_strong(as, &from_read_state_tx, write_same_tx))
        return true;

    // (write, tx") write not allowed
    return false;
}

static void as_reset(access_set_t *as)
{
    atomic_store(as, INIT_STATE);
}

static batcher *get_batcher()
{
    batcher *b = malloc(sizeof(batcher));
    if (unlikely(b == NULL))
        return NULL;

    b->blocked = false;
    b->first = true;
    b->remaining = 0;
    b->tx_id = BASE_TX_ID;

    b->block = malloc(sizeof(struct lock_t));
    if (unlikely(b->block == NULL || !lock_init(b->block)))
    {
        free(b);
        return NULL;
    }

    return b;
}

static void batcher_enter(batcher *b, transaction_t *tx)
{
    lock_acquire(b->block);
    log_info("[%p] batch_enter id: %zu, first=%u, blocked=%u, remaining=%zu", tx, b->first, b->tx_id, b->blocked, b->remaining);

    if (unlikely(b->first))
    {
        b->first = false;
        batcher_block_entry(b);
    }
    else
    {
        while (b->blocked)
            lock_wait(b->block);
    }

    lock_release(b->block);

    lock_acquire(b->block);
    b->remaining += 1;
    tx->id = b->tx_id;
    b->tx_id += 1;

    log_info("[%p, %zu] batch_enter id: %zu, first=%u blocked=%u, remaining=%zu", tx, tx->id, b->tx_id, b->first, b->blocked, b->remaining);
    lock_release(b->block);
}

/**
 * TODO: - grader: modify policy
 * Policy: block on read_only finished
 *  OR last one to leave (?) *
 *  OR on tx abort (?) *
 */
static void batcher_block_entry(batcher *b)
{
    b->blocked = true;
}

static bool batcher_leave(batcher *b, transaction_t *tx, bool force_block)
{
    lock_acquire(b->block);
    b->remaining -= 1;
    bool last = b->remaining == 0;
    if (tx->read_only || force_block)
        batcher_block_entry(b);
    log_debug("[%p, %zu] batcher_leave id: %zu, remaining=%zu, last=%u", tx, tx->id, b->tx_id, b->remaining, last);

    return last;
}

static void batcher_wake_up(batcher *b)
{
    b->blocked = false;
    b->tx_id = BASE_TX_ID;
    log_set_quiet(true);
    lock_release(b->block);
    lock_wake_up(b->block);
}

static void batcher_free(batcher *b)
{
    if (unlikely(b->block == NULL))
    {
        lock_cleanup(b->block);
        free(b->block);
    }
    free(b);
}

static bool lock_init(struct lock_t *lock)
{
    return pthread_mutex_init(&(lock->mutex), NULL) == 0 && pthread_cond_init(&(lock->cv), NULL) == 0;
}

static void lock_cleanup(struct lock_t *lock)
{
    pthread_mutex_destroy(&(lock->mutex));
    pthread_cond_destroy(&(lock->cv));
}

static bool lock_acquire(struct lock_t *lock)
{
    return pthread_mutex_lock(&(lock->mutex)) == 0;
}

static void lock_release(struct lock_t *lock)
{
    pthread_mutex_unlock(&(lock->mutex));
}

static void lock_wait(struct lock_t *lock)
{
    pthread_cond_wait(&(lock->cv), &(lock->mutex));
}

static void lock_wake_up(struct lock_t *lock)
{
    pthread_cond_broadcast(&(lock->cv));
}

static bool segment_alloc(shared_mem *mem, size_t size)
{
    segment seg;

    seg.size = size;
    seg.free = false;
    seg.index = atomic_load(&mem->allocated_segments);
    seg.access_sets = calloc(size, sizeof(access_set_t));
    seg.writeCopies = calloc(size, mem->align);
    seg.readCopies = calloc(size, mem->align);

    if (unlikely(
            seg.access_sets == NULL ||
            seg.writeCopies == NULL ||
            seg.readCopies == NULL))
    {
        free(seg.access_sets);
        free(seg.writeCopies);
        free(seg.readCopies);
        seg.access_sets = NULL;
        seg.writeCopies = NULL;
        seg.readCopies = NULL;
        return true;
    }

    mem->segments[mem->allocated_segments++] = seg;
    return false;
}

static int get_segment_index(void const *addr)
{
    return (int) SEG_INDEX((uintptr_t)addr);
}

static size_t get_word_index(void const *addr, size_t align)
{
    return (size_t)WORD_INDEX_ALIGN((uintptr_t)addr, align);
}

static void segment_set_free(shared_mem *mem, int s_i)
{
    log_error("Setting segment free %u", s_i);
    atomic_store(&mem->segments[s_i].free, true);
}

static void segment_free(shared_mem *mem, int s_i)
{
    segment seg = mem->segments[s_i];
    log_error("Freeing segment %u, has been set: %u", s_i, seg.free);
    free(seg.access_sets);
    free(seg.writeCopies);
    free(seg.readCopies);
    seg.access_sets = NULL;
    seg.writeCopies = NULL;
    seg.readCopies = NULL;
    seg.free = true;
    log_error("Freed segment %u", s_i);
}

static void abort_fail(shared_mem *mem, transaction_t *tx)
{
    tx_abort(mem, tx);
    leave_and_commit(mem, tx, true);
    tx_free(tx);
}

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
 **/
shared_t tm_create(size_t size, size_t align)
{
    log_set_quiet(true);

    shared_mem *mem = malloc(sizeof(shared_mem));
    if (unlikely(mem == NULL))
        return invalid_shared;

    mem->align = align;
    mem->allocated_segments = 0;

    mem->batcher = get_batcher();
    if (unlikely(mem->batcher == NULL))
        goto fail_tm_create;

    if (unlikely(segment_alloc(mem, size)))
        goto fail_tm_create;

    if (unlikely(vec_new(&mem->modif_read.indices, 0, sizeof(size_t)) < 0))
        goto fail_modif_read;

    if (unlikely(vec_new(&mem->modif_write.indices, 0, sizeof(size_t)) < 0))
        goto fail_modif_write;

    if (unlikely(vec_new(&mem->seg_free, 0, sizeof(int)) < 0))
        goto fail_modif_write; // TODO: correct handler

    mem->modif_read.lock = malloc(sizeof(struct lock_t));
    if (unlikely(mem->modif_read.lock == NULL || !lock_init(mem->modif_read.lock)))
        goto fail_read_lock;

    mem->modif_write.lock = malloc(sizeof(struct lock_t));
    if (unlikely(mem->modif_write.lock == NULL || !lock_init(mem->modif_write.lock)))
        goto fail_write_lock;

    return mem;

fail_write_lock:
    lock_cleanup(mem->modif_read.lock);
    free(mem->modif_read.lock);
fail_read_lock:
    vec_free(&mem->modif_write.indices);
fail_modif_write:
    vec_free(&mem->modif_read.indices);
fail_modif_read:
    segment_free(mem, mem->allocated_segments - 1);
fail_tm_create:
    batcher_free(mem->batcher);
    free(mem);
    return invalid_shared;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
 **/
void tm_destroy(shared_t shared)
{
    shared_mem *mem = (shared_mem *)shared;

    batcher_free(mem->batcher);
    mem->batcher = NULL;

    int nb = atomic_load(&mem->allocated_segments);
    log_error("Cleaning %zu segments", nb);
    for (int i = 0; i < nb; i++)
        segment_free(mem, (size_t)i);

    // TODO: generalize this
    lock_cleanup(mem->modif_read.lock);
    lock_cleanup(mem->modif_write.lock);
    vec_free(&mem->modif_read.indices);
    vec_free(&mem->modif_write.indices);
    free(mem->modif_read.lock);
    free(mem->modif_write.lock);

    vec_free(&mem->seg_free);

    mem->allocated_segments = 0;
    mem->align = 0;

    free(mem);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
 **/
void *tm_start(shared_t unused(shared))
{
    return SEG_ADDR(1LL);
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
 **/
size_t tm_size(shared_t shared)
{
    return ((shared_mem *)shared)->segments[0].size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
 **/
size_t tm_align(shared_t shared)
{
    return ((shared_mem *)shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
 **/
tx_t tm_begin(shared_t shared, bool is_ro)
{
    shared_mem *mem = (shared_mem *)shared;
    transaction_t *tx = malloc(sizeof(transaction_t));
    if (unlikely(tx == NULL))
        return invalid_tx;

    log_debug("[%p] tm_begin", tx);

    tx->read_only = is_ro;
    tx->id = 0;

    size_t init_size = is_ro ? 1024 : 2;
    if (unlikely(vec_new(&tx->mod_words, init_size, sizeof(size_t)) < 0))
        goto fail_mod;

    if (unlikely(vec_new(&tx->free_segs, 0, sizeof(size_t)) < 0))
        goto fail_free;

    if (unlikely(vec_new(&tx->alloc_segs, 0, sizeof(size_t)) < 0))
        goto fail_alloc;

    batcher_enter(mem->batcher, tx);

    return (tx_t)tx;

fail_alloc:
    vec_free(&tx->free_segs);
fail_free:
    vec_free(&tx->mod_words);
fail_mod:
    free(tx);
    return invalid_tx;
}

static void commit(shared_mem *mem, transaction_t *tx)
{
    log_info("/////// Committing ////////");

    void **ptr;
    int s_i;
    size_t w_i;
    segment seg;
    size_t a = mem->align;
    t_vec mw = mem->modif_write.indices;
    t_vec mr = mem->modif_read.indices;

    for (size_t i = 0; i < mw.len; i++)
    {
        ptr = (void **)vec_get(&mem->modif_write.indices, i);
        s_i = get_segment_index(*ptr);
        w_i = get_word_index(*ptr, a);
        seg = mem->segments[s_i];
        if (unlikely(seg.free))
            continue;
        _word_print(mem, tx, s_i, w_i);

        if (load_state(seg.access_sets + w_i) == WRITE_STATE)
            memcpy(seg.readCopies + w_i * a, seg.writeCopies + w_i * a, a);

        as_reset(seg.access_sets + w_i);
        _word_print(mem, tx, s_i, w_i);
    }
    vec_clear(&mem->modif_write.indices);

    // reset access set of read words
    for (size_t i = 0; i < mr.len; i++)
    {
        ptr = (void **)vec_get(&mem->modif_read.indices, i);
        s_i = get_segment_index(*ptr);
        w_i = get_word_index(*ptr, a);
        seg = mem->segments[s_i];
        if (unlikely(seg.free))
            continue;
        _word_print(mem, tx, s_i, w_i);
        as_reset(seg.access_sets + w_i);
    }
    vec_clear(&mem->modif_read.indices);

    // actual free of the segments
    int *seg_ptr;
    for (size_t i = 0; i < mem->seg_free.len; i++)
    {
        seg_ptr = (int *)vec_get(&mem->seg_free, i);
        segment_free(mem, *seg_ptr);
        int idx = *seg_ptr + 1;
        log_error("freeing segment: %u (+1 ), allocated: %u, new_idx: %u", idx, mem->allocated_segments, idx - 1 );
        log_set_quiet(false);
        atomic_compare_exchange_strong(&mem->allocated_segments, &idx, idx - 1);
    }
    vec_clear(&mem->seg_free);
}

// leave batcher - no more threads remaining => commit
// returns true if commited succesfully or not allow to commit (not last tx on batcher)
static bool leave_and_commit(shared_mem *mem, transaction_t *tx, bool force_block)
{
    batcher *b = mem->batcher;

    bool last = batcher_leave(b, tx, force_block);

    // set free segments
    int *ptr;
    for (size_t i = 0; i < tx->free_segs.len; i++)
    {
        ptr = (int *)vec_get(&tx->free_segs, i);
        log_error("leave_and_commit, seg to free: %u", *ptr);
        segment_set_free(mem, *ptr);
    }
    vec_free(&tx->free_segs);

    if (last)
    {
        commit(mem, tx);
        print_mem(mem, tx);
        batcher_wake_up(b);
        return true;
    }
    else
    {
        lock_release(b->block);
        return false;
    }
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
 **/
bool tm_end(shared_t shared, tx_t tx)
{
    shared_mem *mem = (shared_mem *)shared;
    transaction_t *ts = (transaction_t *)tx;

    bool committed = leave_and_commit(mem, ts, false);
    log_debug("[%p, %zu] tm_end committed? %u", tx, ts->id, committed);

    tx_free(ts);

    return committed;
}

static bool read_word(segment seg, size_t w_i, void *read_to, transaction_t *tx, size_t align)
{
    // if ( tx->read_only )
    //     memcpy(read_to, seg.readCopies + w_i * align, align);
    // else
    // {
    char state = as_read_op(seg.access_sets + w_i, tx);
    if (state == INVALID_STATE)
        return true;
    else if (state == WRITE_STATE)
        memcpy(read_to, seg.writeCopies + w_i * align, align);
    else if (state == READ_STATE || state == DOUBLE_READ_STATE)
        memcpy(read_to, seg.readCopies + w_i * align, align);
    // }

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
bool tm_read(shared_t shared, tx_t tx, void const *source, size_t size, void *target)
{
    shared_mem *mem = (shared_mem *)shared;
    transaction_t *ts = (transaction_t *)tx;

    size_t a = mem->align;
    size_t max_offset = size / a;
    int s_i = get_segment_index(source);
    size_t base_w_i = get_word_index(source, a);
    segment seg = mem->segments[s_i];

    log_debug("[%p, %zu] tm_read  (%u, %zu) seg_free: %u", ts, ts->id, s_i, base_w_i, atomic_load(&seg.free));

    if (unlikely(atomic_load(&seg.free)))
    {
        log_fatal("[%p, %zu] tm_read  (%u, %zu) fail because of segment freed", ts, ts->id, s_i, base_w_i)
        abort_fail(mem, ts);
        return false;
    }

    for (size_t offset = 0; offset < max_offset; offset++)
    {
        size_t w_i = base_w_i + offset;
        if (unlikely(
                read_word(seg, w_i, target + offset * a, ts, a) ||
                word_save_read_modif(mem, source) ||
                tx_mod_word(ts, source)))
        {
            log_fatal("[%zu] read failed, (%u, %zu)", ts->id, s_i, w_i);
            abort_fail(mem, ts);
            return false;
        }

        _word_print(mem, ts, s_i, base_w_i);
    }

    return true;
}

static bool write_word(segment seg, size_t w_i, void const *src, transaction_t *tx, size_t align)
{
    if (as_write_op(seg.access_sets + w_i, tx))
    {
        memcpy(seg.writeCopies + w_i * align, src, align);
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
bool tm_write(shared_t shared, tx_t tx, void const *source, size_t size, void *target)
{
    shared_mem *mem = (shared_mem *)shared;
    transaction_t *ts = (transaction_t *)tx;

    size_t a = mem->align;
    size_t max_offset = size / a;
    int s_i = get_segment_index(target);
    size_t base_w_i = get_word_index(target, a);
    segment seg = mem->segments[s_i];

    if (unlikely(atomic_load(&seg.free)))
    {
        log_fatal("[%p, %zu] tm_write  (%u, %zu) fail because of segment freed", ts, ts->id, s_i, base_w_i)
        abort_fail(mem, ts);
        return false;
    }

    log_info("[%p, %zu] tm_write  target=(%u, %zu), writing=%zu, size: %zu", ts, ts->id, s_i, base_w_i, *((size_t *)(source)), size);
    for (size_t offset = 0; offset < max_offset; offset++)
    {
        size_t w_i = base_w_i + offset;
        if (unlikely(
                write_word(seg, w_i, source + offset * a, ts, a) ||
                word_save_write_modif(mem, target) ||
                tx_mod_word(ts, target)))
        {
            log_fatal("[%zu] write failed (%u, %zu)", ts->id, s_i, w_i);
            abort_fail(mem, ts);
            return false;
        }

        _word_print(mem, ts, s_i, w_i);
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
alloc_t tm_alloc(shared_t shared, tx_t tx, size_t size, void **target)
{
    log_error("[%p]  tm_alloc  start", tx);

    shared_mem *mem = (shared_mem *)shared;
    transaction_t *ts = (transaction_t *)tx;

    if (unlikely(segment_alloc(mem, size)))
    {
        abort_fail(mem, ts);
        return nomem_alloc;
    }

    int s_i = mem->allocated_segments - 1;
    if (unlikely(vec_push(&ts->alloc_segs, &s_i) < 0))
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
bool tm_free(shared_t shared, tx_t tx, void *target)
{
    shared_mem *mem = (shared_mem *)shared;
    transaction_t *ts = (transaction_t *)tx;
    int s_i = get_segment_index(target);
    log_set_quiet(false);
    log_error("[%p] tm_free %u", ts, s_i);
    // return vec_push(&ts->free_segs, &s_i) >= 0;
    segment_set_free(mem, s_i);
    return vec_push(&mem->seg_free, &s_i) >= 0;
}

static bool tx_mod_word(transaction_t *tx, void *addr)
{
    size_t *s = (size_t *)addr;
    return vec_push(&tx->mod_words, &s) < 0;
}

static void tx_abort(shared_mem *mem, transaction_t *tx)
{
    // free allocated segments
    int *seg_ptr;
    for (size_t i = 0; i < tx->alloc_segs.len; i++)
    {
        seg_ptr = (int *)vec_get(&tx->alloc_segs, i);
        segment_set_free(mem, *seg_ptr);
    }
    vec_free(&tx->alloc_segs);

    // TODO: don't care if very slow
    // if more than 2>>16 alloc -> find free segments

    size_t a = mem->align;
    t_vec mod = tx->mod_words;
    void **ptr;
    int s_i;
    size_t w_i;
    segment seg;
    for (size_t i = 0; i < mod.len; i++)
    {
        ptr = (void **)vec_get(&tx->mod_words, i);
        s_i = get_segment_index(*ptr);
        w_i = get_word_index(*ptr, a);
        seg = mem->segments[s_i];
        if ( unlikely(seg.free) ) continue;
        log_debug("[%p, %zu] Reverting idx: %zu, (%u, %zu)", tx, tx->id, i, s_i, w_i);
        as_revert(seg.access_sets + w_i, tx);
        _word_print(mem, tx, s_i, w_i);
    }
}

static void tx_free(transaction_t *tx)
{
    vec_free(&tx->free_segs);
    vec_free(&tx->alloc_segs);
    vec_free(&tx->mod_words);
    free(tx);
}

static bool word_save_read_modif(shared_mem *mem, void const *source)
{
    lock_acquire(mem->modif_read.lock);
    size_t *s = (size_t *)source;
    int err = vec_push(&mem->modif_read.indices, &s);
    lock_release(mem->modif_read.lock);
    return err < 0;
}

static bool word_save_write_modif(shared_mem *mem, void *target)
{
    lock_acquire(mem->modif_write.lock);
    size_t *s = (size_t *)target;
    int err = vec_push(&mem->modif_write.indices, &s);
    lock_release(mem->modif_write.lock);
    return err < 0;
}