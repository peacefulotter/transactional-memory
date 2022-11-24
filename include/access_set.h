
#pragma once

#include <stdbool.h>

#include "tm.h"

#define INIT_STATE 0
#define READ_STATE 1
#define DOUBLE_READ_STATE 2
#define WRITE_STATE 3
#define INVALID_STATE 4

#define SHIFT 8
#define as_format(tx, as) (((size_t) tx) << SHIFT | as)
#define as_extract_tx(as) (size_t) as >> SHIFT
#define as_extract_state(as) (((size_t) as) & 0xFF)

bool as_contains(access_set_t* as, transaction_t* tx );
char as_read_op(access_set_t* as, transaction_t* tx);
bool as_write_op(access_set_t* as, transaction_t* tx);
void as_reset(access_set_t* as);
void as_print(transaction_t* tx, access_set_t* as);