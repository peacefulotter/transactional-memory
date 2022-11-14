#include <stdbool.h>
#include "tm.h"

bool as_contains( access_set_t as, transaction_t* tx );
bool as_add( access_set_t as, transaction_t* tx );
void as_release(access_set_t as);
void as_print(access_set_t as);