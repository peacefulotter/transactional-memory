#include <stdlib.h>

#include "tm.h"
#include "access_set.h"

bool as_contains( access_set_t* as, transaction* tx )
{
    for (size_t i = 0; i < as->size; i++)
    {
        if ( as->set[i].id == tx->id )
            return true;
    }
    return false;
}

bool as_add( access_set_t* as, transaction* tx )
{
    as->set = realloc(as->set, (as->size + 1) * sizeof(transaction));
    if ( as->set == NULL )
    {
        as_release(as);
        return false;
    }
    as->set[as->size] = *tx;
    as->size++;
    return true;
}

void as_release(access_set_t* as)
{
    as->size = 0;
    free( as->set );
    free(as);
}