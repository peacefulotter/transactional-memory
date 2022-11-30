
#pragma once

#include "tm.h"

void transaction_add_word(transaction_t* tx, size_t s_i, size_t w_i, bool modif_type);
void transaction_abort(shared_mem* mem, transaction_t* tx);