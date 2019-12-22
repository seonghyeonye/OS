#include <hash.h>

struct sppt_entry{
   void *upage;
   void *kpage;
   struct hash_elem elem; 
}



