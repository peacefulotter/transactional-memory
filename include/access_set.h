#include <stdbool.h>
#include "tm.h"

#define INIT_STATE 0
#define READ_STATE 1
#define DOUBLE_READ_STATE 2
#define WRITE_STATE 3
#define INVALID_STATE 4

access_set_t* as_init();
void as_set_tx(access_set_t* as, transaction_t* tx);
bool as_contains( access_set_t* as, transaction_t* tx );
bool as_read_op(access_set_t* as, transaction_t* tx);
bool as_write_op(access_set_t* as, transaction_t* tx);
void as_print(transaction_t* tx, access_set_t* as);