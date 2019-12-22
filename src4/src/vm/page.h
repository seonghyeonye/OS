#ifndef VM_PAGE_H
#define VM_PAGE_H
#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

#include <hash.h>
#include "filesys/file.h"

extern struct lock lru_lock;
struct sppt_entry{
   uint8_t type;
   void *upage;
   //void *kpage;
   //struct frame_entry *f; 
   struct hash_elem elem;
   struct file *file;
   size_t offset;
   size_t read_bytes;
   size_t zero_bytes;
   size_t swap_slot;
   struct list_elem mmap_elem;
   bool writable;
   bool ref_bit;
   bool stk_flag;
};

struct mmap_file{
   int mapid;
   struct file *file;
   struct list_elem elem;
   struct list vme_list;
};
 

unsigned vm_hash_func(const struct hash_elem *e, void *aux);
bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b,void *aux);
void vm_init(struct hash *vm);
void vm_destroy(struct hash *vm);
bool load_file(void* kaddr, struct sppt_entry *vme);
bool load_file(void* kaddr, struct sppt_entry *vme);

#endif
