
#pragma once

#include "mem.h"
#include "tm.h"

tx_t transaction_init(shared_mem* mem, bool is_ro);
void tx_register_write_word(transaction_t* tx, size_t idx);
// void transaction_register_read_word(transaction_t* tx, size_t idx);
void tx_abort(shared_mem* mem, transaction_t* tx);