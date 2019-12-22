#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

struct lock lru_lock;
struct list lru_list;
struct list_elem *clock;
struct hash lru_hash;

unsigned frame_hash_func(const struct hash_elem *e, void *aux){
  struct frame_entry *e_entry = hash_entry(e,struct frame_entry,hash);
  return hash_int((int)e_entry->kpage);
}

bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b,void *aux){
  struct frame_entry *a_entry = hash_entry(a,struct frame_entry,hash);
  struct frame_entry *b_entry = hash_entry(b,struct frame_entry,hash);
  return a_entry->kpage < b_entry->kpage;
}

void lru_init(void){
  lock_init(&lru_lock);
  list_init(&lru_list);
  hash_init(&lru_hash,frame_hash_func,frame_less_func,NULL);
  clock=NULL;
}


struct frame_entry *alloc_frame_entry(enum palloc_flags flags){
  lock_acquire(&lru_lock);
  void *frame=palloc_get_page(flags);
  if(frame==NULL){
     try_to_free_pages();
     frame= palloc_get_page(PAL_USER);
     if(frame==NULL)
        printf("fail!!!!!!\n");
  }
  struct frame_entry *entry= (struct frame_entry *)malloc(sizeof(struct frame_entry));
  if(entry==NULL){
    printf("frame entry malloc failed\n");
  }
  memset(entry,0,sizeof(struct frame_entry));
  entry->t = thread_current();
  entry->kpage=frame;
  list_push_back(&lru_list,&entry->elemlist);
  hash_insert(&lru_hash,&entry->hash);
  lock_release(&lru_lock);
  return entry;
}    



void free_frame(void *kpage){
  lock_acquire(&lru_lock);
  free_after_lock(kpage);
  lock_release(&lru_lock);
}

void free_after_lock(void *kpage){
  struct frame_entry temp;
  temp.kpage=kpage;
  struct hash_elem *elem = hash_find(&lru_hash,&temp.hash);
  if(elem!=NULL){
  struct frame_entry *found = hash_entry(elem,struct frame_entry,hash);
  hash_delete(&lru_hash,&found->hash);
  pagedir_clear_page(found->t->pagedir,found->entry->upage);
  list_remove(&found->elemlist);
  palloc_free_page(kpage);
  free(found);
  }
}

struct list_elem *get_next_lru_clock(){
  ASSERT (lock_held_by_current_thread (&lru_lock));
  if(clock==NULL||clock==list_end(&lru_list)){
     if(list_empty(&lru_list))
        return NULL;
     return clock =list_begin(&lru_list);
     }
  clock=list_next(clock);
  if(clock==list_end(&lru_list))
       return get_next_lru_clock();
  return clock;
}

void try_to_free_pages(){
  ASSERT(lock_held_by_current_thread(&lru_lock));
  size_t length=list_size(&lru_list);
  for(int i=0;i<2*length;i++){
    struct list_elem *e = get_next_lru_clock();
    struct frame_entry *test_entry = list_entry(e,struct frame_entry,elemlist);
    if(test_entry->entry->ref_bit==false){
      ASSERT(test_entry->entry!=NULL);
      ASSERT(test_entry->t!=NULL);
      switch(test_entry->entry->type){
         case VM_BIN:
           if(pagedir_is_dirty(test_entry->t->pagedir,test_entry->entry->upage)){
              test_entry->entry->swap_slot=swap_out(test_entry->kpage);
              test_entry->entry->type = VM_ANON;
           }
           break;
         case VM_ANON:
           test_entry->entry->swap_slot=swap_out(test_entry->kpage);
           break;
         case VM_FILE:
           if(pagedir_is_dirty(test_entry->t->pagedir,test_entry->entry->upage)){
              if(file_write_at(test_entry->entry->file,test_entry->entry->upage,test_entry->entry->read_bytes,test_entry->entry->offset)!=(int)test_entry->entry->read_bytes){
                 printf("writing to file in try to free failed\n");
              }
           }
           break;
         default:
           printf("failed!\n"); 
       }
       free_after_lock(test_entry->kpage);
       break;
    }
    else{
    test_entry->entry->ref_bit=false; 
    pagedir_set_accessed(test_entry->t->pagedir,test_entry->entry->upage,false);
    }
  }
}
