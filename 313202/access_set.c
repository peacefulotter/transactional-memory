#include <stdlib.h>
#include <stdio.h>

#include "tm.h"
#include "access_set.h"
#include "vec.h"
#include "logger.h"

bool as_contains( access_set_t as, transaction_t* tx )
{
    for (size_t i = 0; i < vector_size(as); i++)
    {
        if ( as[i] == tx )
            return true;
    }
    return false;
}

bool as_add( access_set_t as, transaction_t* tx )
{
    // as->set = realloc(as->set, (as->size + 1) * sizeof(transaction_t));
    // if ( as->set == NULL )
    // {
    //     as_release(as);
    //     return false;
    // }
    // as->set[as->size] = tx;
    // as->size++;
    // return true;
    vector_add(&as, tx);
    return true;
}

void as_release(access_set_t as)
{
    // as->size = 0;
    // free( as->set );
    // free( as );
    vector_free(as);
}

void as_print(access_set_t as)
{
    log_debug("AS: size=%u", vector_size(as));
    for (size_t i = 0; i < vector_size(as); i++)
    {
        log_debug("%p, ", as[i]);
    }
}