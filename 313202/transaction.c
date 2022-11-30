


#include "transaction.h"
#include "access_set.h"
#include "tm.h"

void transaction_add_word(transaction_t* tx, size_t s_i, size_t w_i, bool modif_type)
{
    size_t s = tx->modified.size;
    tx->modified.segment_indices[s] = s_i;
    tx->modified.word_indices[s] = w_i;
    tx->modified.modif_type[s] = modif_type;
    tx->modified.size++;
}


void transaction_abort(shared_mem* mem, transaction_t* tx)
{
    size_t s = tx->modified.size;
    for (size_t i = 0; i < s; i++)
    {
        // undo 
        bool s_i = tx->modified.segment_indices[i];
        bool w_i = tx->modified.word_indices[i];
        bool modif = tx->modified.modif_type[i];

        access_set_t as = mem->segments[s_i].access_sets[w_i];
        if ( modif == READ_MODIF )
            as_revert_read(as, tx);
        else if ( modif == WRITE_MODIF )
            as_revert_write(as, tx);
    }
    
}