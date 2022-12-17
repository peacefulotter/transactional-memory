#pragma once


// TODO: [grader] find max modif
// TODO: [grader] TOUT dans un fichier + static
// static = pas utiliser en dehors du fichier

/*
make build-libs
gdb ./grading 
run 453 ../313202.so ../reference.so
*/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "lock.h"

#define MAX_SEGMENTS (2 << 16)
#define MAX_WORDS (2 << 48)
#define MAX_MODIFIED_PER_EPOCH (2 << 20) // 13
#define MAX_MODIFIED_PER_TX (2 << 17) // 9
#define MAX_FREE_SEG (2 << 5)

typedef struct shared_mem shared_mem;
typedef struct segment segment;
typedef struct transaction_t transaction_t;
typedef struct batcher batcher;
typedef atomic_size_t access_set_t;

struct batcher
{
    bool blocked;

    size_t epoch;
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
    segment* seg_free[MAX_FREE_SEG];
};

struct segment
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
    size_t max_read;
    size_t max_write;

    size_t align;

    batcher* batcher;

    struct modified_words_lock modif_read; 
    struct modified_words_lock modif_write;

    atomic_int allocated_segments;
    segment segments[MAX_SEGMENTS];
};