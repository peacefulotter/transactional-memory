#include <access_set.h>

bool as_contains( access_set_t* access_set, tx_t tx )
{
    access_set_t* current = access_set;
    while ( current != NULL ) 
    {
        if ( current->tx == tx )
            return true;
        current = current->next;
    };
    return false;
}

// TODO: add
void add( access_set_t* access_set, tx_t tx )
{
    
}