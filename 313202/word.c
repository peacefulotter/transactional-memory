
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

    word->access_set = 0;
    word->readCopy = calloc(1, align);
    if ( word->readCopy == NULL )
    {
        free(word);
        return NULL;
    }
    word->writeCopy = calloc(1, align);
    if ( word->writeCopy == NULL )
    {
        free(word);
        free(word->readCopy);
        return NULL;
    }

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
    size_t s = atomic_load(&word.access_set);
    log_debug(
        "[%p] word_addr=%p, readCopy=(%p, %zu), writeCopy=(%p, %zu), access=(state=%zu, tx=%p)", 
        tx, &word,
        word.readCopy, *((size_t*) word.readCopy), 
        word.writeCopy, *((size_t*) word.writeCopy),
        as_extract_state(s), as_extract_tx(s)
    );
}