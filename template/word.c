
#include <word.h>

shared_mem_word* initialize_word()
{
    shared_mem_word* word = malloc(sizeof(shared_mem_word*));
    word->ctrl_access_set = malloc(sizeof(access_set_t));
    if ( word->ctrl_access_set == NULL )
    {
        free(word);
        return NULL;
    }
    word->ctrl_nb_accessed = 0;
    word->ctrl_valid = 0;
    word->ctrl_written = false;
    word->readCopy = NULL;
    word->writeCopy = NULL;
    return word;
}