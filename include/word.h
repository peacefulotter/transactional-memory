#include "tm.h"

shared_mem_word* initialize_word(size_t align);
void release_word(shared_mem_word* word);
void print_word(shared_mem_word word);