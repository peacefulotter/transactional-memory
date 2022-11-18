#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>

#include "tm.h"
#include "access_set.h"
#include "vec.h"
#include "logger.h"

access_set_t* as_init()
{
    access_set_t* as = malloc(sizeof(access_set_t));
    atomic_init(&as->state, 0);
    atomic_init(&as->tx, NULL);
    return as;
}

void as_set_tx(access_set_t* as, transaction_t* tx)
{
    atomic_store(&as->tx, tx);
}

bool as_contains( access_set_t* as, transaction_t* tx )
{
    return atomic_load(&as->tx) == tx;
}

bool as_read_op(access_set_t* as, transaction_t* tx)
{
    char init_state = INIT_STATE; 
    char read_state = READ_STATE; 
    char write_state = WRITE_STATE; 

    // 0 -> 1
    if ( atomic_compare_exchange_strong(&as->state, &init_state, READ_STATE) )
    {
        as_set_tx(as, tx);
        return true;
    }
    else if ( atomic_load(&as->state) == READ_STATE )
    {
        // 1 -> 1 
        if ( as_contains(as, tx) ) return true;
        // 1 -> 2
        else {
            atomic_compare_exchange_strong(&as->state, &read_state, DOUBLE_READ_STATE);
            return true;
        }
    }
    else if ( atomic_load(&as->state) == WRITE_STATE )
    {
        // 3 -> 3
        if ( as_contains(as, tx) ) return true;
        // 3 -> 4
        else
        {
            // atomic_compare_exchange_strong(&as->state, &write_state, INVALID_STATE);
            return false;
        }
        return false;
    }

    return false;
}

bool as_write_op(access_set_t* as, transaction_t* tx)
{
    char init_state = INIT_STATE; 
    char read_state = READ_STATE; 
    char write_state = WRITE_STATE; 

    // 0 -> 3
    if ( atomic_compare_exchange_strong(&as->state, &init_state, WRITE_STATE) )
    {
        as_set_tx(as, tx);
        return true;
    }
    else if ( as_contains(as, tx)  )
    {
        // 3 -> 3
        if ( atomic_load(&as->state) == WRITE_STATE )
            return true;
        // 1 -> 3
        else if ( atomic_load(&as->state) == READ_STATE )
        {
            atomic_compare_exchange_strong(&as->state, &read_state, WRITE_STATE);
            return true;
        }
    }
    else
    {
        // 2 -> 4, 1 -> 4, 3 -> 4
        // atomic_store(&as->state, INVALID_STATE);
        return false;
    }
}

void as_print(transaction_t* tx, access_set_t* as)
{
    log_debug("[%p] AS: state=%u, tx=%p", tx, atomic_load(&as->state), atomic_load(&as->tx));
}