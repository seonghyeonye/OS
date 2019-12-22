#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

struct frame_entry{
  struct thread *t;
  //void *upage;
  void *kpage;
  struct list_elem elemlist;
  struct hash_elem hash;
  //bool ref_bit;
  struct sppt_entry *entry;
};

struct hash lru_hash;
void lru_init(void);
struct frame_entry *alloc_frame_entry(enum palloc_flags flag);
void free_frame(void*);
void try_to_free_pages();
void free_after_lock(void *kpage);


#endif
