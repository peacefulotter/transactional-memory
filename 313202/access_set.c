#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>

#include "tm.h"
#include "access_set.h"
#include "vec.h"
#include "logger.h"


bool as_contains( access_set_t* as, transaction_t* tx )
{
    return load_tx(as) == ((size_t) tx);
}

void as_revert_write(access_set_t* as, transaction_t* tx)
{
    // log_fatal("[%p] reverting word", tx);
    // 3 -> 0,  3 -> 1 -> 0
    size_t init_state = INIT_STATE; 
    size_t write_same_tx = as_format(tx, WRITE_STATE); 
    if ( atomic_compare_exchange_strong(as, &write_same_tx, init_state) )
        return;
}

char as_read_op(access_set_t* as, transaction_t* tx)
{
    size_t init_state = INIT_STATE; 
    size_t read_same_tx = as_format(tx, READ_STATE); 

    // 0 -> 1 (init, _) -> (read, tx)
    if ( atomic_compare_exchange_strong(as, &init_state, read_same_tx) )
        return READ_STATE;

    // 1 -> 1 (read, tx) -> (read, tx)
    else if ( init_state == read_same_tx )
        return READ_STATE;

    // 2 -> 2
    else if ( as_extract_state(init_state) == DOUBLE_READ_STATE )
        return DOUBLE_READ_STATE;

    // 1 -> 2 (read, tx) -> (d_read, tx")
    size_t read_other_tx = as_format(as_extract_tx(init_state), READ_STATE);
    size_t double_read_other_tx = as_format(as_extract_tx(init_state), DOUBLE_READ_STATE);
    if ( atomic_compare_exchange_strong(as, &read_other_tx, double_read_other_tx ) )
        return DOUBLE_READ_STATE;

    // 3 -> 3 (write, tx) -> (write, tx)
    else if ( read_other_tx == as_format(as_extract_tx(read_other_tx), WRITE_STATE) )
        return WRITE_STATE;

    // read not allowed - pretend to be in invalid state
    return INVALID_STATE;
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
    
    // write not allowed
    return false;
}

void as_reset(access_set_t* as)
{
    atomic_store(as, INIT_STATE);
}

void as_print(access_set_t* as, transaction_t* tx)
{
    size_t s = atomic_load(as);
    log_debug("[%p] AS: state=%u, tx=%p", tx, as_extract_state(s), as_extract_tx(s));
}