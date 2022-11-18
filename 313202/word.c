
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>

#include "word.h"
#include "macros.h"
#include "access_set.h"
#include "vec.h"
#include "logger.h"

shared_mem_word* word_init(size_t align)
{
    shared_mem_word* word = malloc(sizeof(shared_mem_word));
    if ( unlikely(word == NULL) )
        return NULL;

    word->access_set = as_init();
    word->readCopy = calloc(1, align);
    word->writeCopy = calloc(1, align);

    return word;
}

void word_free(shared_mem_word word)
{
    free(word.readCopy);
    free(word.writeCopy);
    word.readCopy = NULL;
    word.writeCopy = NULL;
}

void word_print(transaction_t* tx, shared_mem_word word)
{
    log_debug(
        "readCopy=(%p, %zu), writeCopy=(%p, %zu), access=(%zu, %p)", 
        word.readCopy, *((size_t*) word.readCopy), 
        word.writeCopy, *((size_t*) word.writeCopy),
        atomic_load(&word.access_set->state), atomic_load(&word.access_set->tx)
    );
}