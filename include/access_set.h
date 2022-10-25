#include <stdbool.h>
#include "tm.h"

bool as_contains( access_set_t* as, transaction* tx );
bool as_add( access_set_t* as, transaction* tx );
void as_release(access_set_t* as);