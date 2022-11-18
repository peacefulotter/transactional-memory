#include "tm.h"

shared_mem_word* word_init(size_t align);
void word_free(shared_mem_word word);
void word_print(transaction_t* tx, shared_mem_word word);