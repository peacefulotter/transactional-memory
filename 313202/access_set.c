#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>

#include "tm.h"
#include "access_set.h"
#include "vec.h"
#include "logger.h"


bool as_contains( access_set_t* as, transaction_t* tx )
{
    return as_extract_tx( atomic_load(as) ) == (size_t) tx;
}

bool as_read_op(access_set_t* as, transaction_t* tx)
{
    size_t init_state = INIT_STATE; 
    size_t read_same_tx = as_format(tx, READ_STATE); 

    // 0 -> 1 (init, _) -> (read, tx)
    if ( atomic_compare_exchange_strong(as, &init_state, read_same_tx) )
        return true;

    // 1 -> 1 (read, tx) -> (read, tx)
    else if ( init_state == read_same_tx )
        return true;

    // 2 -> 2
    else if ( as_extract_state(init_state) == DOUBLE_READ_STATE )
        return true;

    // 1 -> 2 (read, tx) -> (d_read, tx")
    size_t read_other_tx = as_format(as_extract_tx(init_state), READ_STATE);
    size_t double_read_other_tx = as_format(as_extract_tx(init_state), DOUBLE_READ_STATE);
    if ( atomic_compare_exchange_strong(as, &read_other_tx, double_read_other_tx ) )
        return true;

    // 3 -> 3 (write, tx) -> (write, tx)
    else if ( read_other_tx == as_format(as_extract_tx(read_other_tx), WRITE_STATE) )
        return true;

    return false;
}

bool as_write_op(access_set_t* as, transaction_t* tx)
{
    size_t init_state = INIT_STATE; 
    size_t write_same_tx = as_format(tx, WRITE_STATE); 

    // 0 -> 3 (init, _) -> (write, tx)
    if ( atomic_compare_exchange_strong(as, &init_state, write_same_tx) )
        return true;

    // 3 -> 3 (write, tx) -> (write, tx)
    else if ( init_state == write_same_tx  )
        return true;

    // 1 -> 3 (read, tx) -> (write, tx)
    size_t from_read_state_tx = as_format(tx, READ_STATE);
    if ( atomic_compare_exchange_strong(as, &from_read_state_tx, write_same_tx) )
        return true;
    
    return false;
}

void as_reset(access_set_t* as)
{
    atomic_store(as, INIT_STATE);
}

void as_print(transaction_t* tx, access_set_t* as)
{
    size_t s = atomic_load(as);
    log_debug("[%p] AS: state=%u, tx=%p", tx, as_extract_state(s), as_extract_tx(s));
}