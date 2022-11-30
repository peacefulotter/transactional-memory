
#pragma once

#include "tm.h"

tx_t transaction_init(shared_mem* mem, bool is_ro);
void transaction_add_word(transaction_t* tx, size_t s_i, size_t w_i, bool is_read);
void transaction_abort(shared_mem* mem, transaction_t* tx);