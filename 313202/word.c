
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

    atomic_init(&word->ctrl_written, 0);
    atomic_init(&word->ctrl_valid, false);
    atomic_init(&word->ctrl_written , false);

    word->ctrl_access_set = vector_create();
    word->readCopy = calloc(1, align);
    word->writeCopy = calloc(1, align);

    return word;
}

void word_free(shared_mem_word word)
{
    as_release(word.ctrl_access_set);
}

void word_print(shared_mem_word word)
{
    log_debug(
        "valid=%d, written=%d, readCopy=(%p, %zu), writeCopy=(%p, %zu)", 
         atomic_load(&word.ctrl_valid), atomic_load(&word.ctrl_written), word.readCopy, *((size_t*) word.readCopy), word.writeCopy, *((size_t*) word.writeCopy)
    );
    as_print(word.ctrl_access_set);
}