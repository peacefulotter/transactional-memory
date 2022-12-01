

#include "tm.h"

size_t word_save_modif(shared_mem* mem, size_t s_i, size_t w_i, bool is_read);
void word_print(shared_mem* mem, transaction_t* tx, shared_mem_segment seg, size_t word_index);