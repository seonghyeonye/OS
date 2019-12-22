#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"


unsigned vm_hash_func(const struct hash_elem *e, void *aux){
  struct sppt_entry *e_entry = hash_entry(e,struct sppt_entry,elem);
  return hash_int((int)e_entry->upage);
}

bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b,void *aux){
  struct sppt_entry *a_entry = hash_entry(a,struct sppt_entry,elem);
  struct sppt_entry *b_entry = hash_entry(b,struct sppt_entry,elem);
  return a_entry->upage < b_entry->upage;
}

void vm_init(struct hash *vm){  
  hash_init(vm,vm_hash_func,vm_less_func,NULL);
}

bool insert_vme(struct hash *vm,struct sppt_entry *entry){
  struct hash_elem *insert_elem = hash_insert(vm,&entry->elem);
  if(insert_elem==NULL)
      return true;
  return false;
}


bool delete_vme(struct hash *vm, struct sppt_entry *vme){
  struct hash_elem *delete_elem = hash_delete(vm,&vme->elem);
  if(delete_elem==NULL)
     return false;
  free_after_lock(pagedir_get_page(thread_current()->pagedir,vme->upage));
  free(vme);
  return true;
}

struct sppt_entry *find_vme(void *upage){
  struct hash *vm = &thread_current()->vm;
  
  struct sppt_entry temp;
  temp.upage = pg_round_down(upage);
  struct hash_elem *elem = hash_find(vm,&temp.elem);
  if(elem==NULL) {
    return NULL;
  }
  struct sppt_entry *elem_entry = hash_entry(elem,struct sppt_entry,elem);
  return elem_entry;
}

void destroy_func(struct hash_elem *elems, void *aux){
  struct sppt_entry *temp = hash_entry(elems,struct sppt_entry,elem);
  if(temp->upage!=NULL){
     free_frame(pagedir_get_page(thread_current()->pagedir,temp->upage));
  }
  free(temp);
}

void vm_destroy(struct hash *vm){
  hash_destroy(vm,destroy_func);
}

bool load_file(void* kaddr, struct sppt_entry *vme){
 if(file_read_at(vme->file,kaddr,vme->read_bytes,vme->offset)!=(int)vme->read_bytes){
   printf("load failed!\n");
   return false;
 }
 memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);
 return true;
 }


