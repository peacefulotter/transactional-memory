/**
 * @file   tm.h
 * @author Sébastien ROUAULT <sebastien.rouault@epfl.ch>
 * @author Antoine MURAT <antoine.murat@epfl.ch>
 *
 * @section LICENSE
 *
 * Copyright © 2018-2021 Sébastien ROUAULT.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * any later version. Please see https://gnu.org/licenses/gpl.html
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * @section DESCRIPTION
 *
 * Interface declaration for the transaction manager to use (C version).
 * YOU SHOULD NOT MODIFY THIS FILE.
**/

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#define MAX_SEGMENTS 2 << 16
#define MAX_WORDS 2 << 48
#define MAX_MODIFIED 2 << 10
#define MAX_FREE_SEG 2 << 5

typedef struct shared_mem shared_mem;
typedef struct shared_mem_word shared_mem_word;
typedef struct shared_mem_segment shared_mem_segment;
typedef struct transaction_t transaction_t;
typedef struct batcher batcher;
typedef atomic_size_t access_set_t;

struct batcher
{
    size_t counter;
    size_t remaining;
    size_t nb_blocked;

    struct lock_t* mutex;
    struct lock_t* round_lock;
};

struct transaction_t
{
    bool read_only;
    size_t seg_free_size;
    shared_mem_segment* seg_free[MAX_FREE_SEG];
};

struct shared_mem_word 
{
    access_set_t access_set;

    void* readCopy; 
    void* writeCopy;
};

struct shared_mem_segment
{
    size_t size;
    shared_mem_word* words;
};

struct modified_words
{
    shared_mem_word* words[MAX_MODIFIED];
    size_t size;
    struct lock_t* lock;
};


struct shared_mem
{
    size_t align;

    batcher* batcher;

    struct modified_words modif_read; 
    struct modified_words modif_write;

    atomic_int allocated_segments;
    shared_mem_segment segments[MAX_SEGMENTS];
};

// -------------------------------------------------------------------------- //

typedef void* shared_t; // The type of a shared memory region
static shared_t const invalid_shared = NULL; // Invalid shared memory region

// Note: a uintptr_t is an unsigned integer that is big enough to store an
// address. Said differently, you can either use an integer to identify
// transactions, or an address (e.g., if you created an associated data
// structure).
typedef uintptr_t tx_t; // The type of a transaction identifier
static tx_t const invalid_tx = ~((tx_t) 0); // Invalid transaction constant
// static const tx_t read_only_tx  = UINTPTR_MAX - 10;
// static const tx_t read_write_tx = UINTPTR_MAX - 11;

typedef int alloc_t;
static alloc_t const success_alloc = 0; // Allocation successful and the TX can continue
static alloc_t const abort_alloc   = 1; // TX was aborted and could be retried
static alloc_t const nomem_alloc   = 2; // Memory allocation failed but TX was not aborted

// -------------------------------------------------------------------------- //

shared_t tm_create(size_t, size_t);
void     tm_destroy(shared_t);
void*    tm_start(shared_t);
size_t   tm_size(shared_t);
size_t   tm_align(shared_t);
tx_t     tm_begin(shared_t, bool);
bool     tm_end(shared_t, tx_t);
bool     tm_read(shared_t, tx_t, void const*, size_t, void*);
bool     tm_write(shared_t, tx_t, void const*, size_t, void*);
alloc_t  tm_alloc(shared_t, tx_t, size_t, void**);
bool     tm_free(shared_t, tx_t, void*);