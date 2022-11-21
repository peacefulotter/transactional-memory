

#define WORD_POWER 48
#define SEG_ADDR(l) (long long) l << WORD_POWER
#define SEG_INDEX(addr) (((uintptr_t) addr) >> WORD_POWER) - 1
#define WORD_INDEX(addr) (((uintptr_t) addr) & 0xFFFFFFFFFFFF) >> 3