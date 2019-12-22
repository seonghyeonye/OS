#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

#define CACHE_ENTRY_NB 64

int clock;
struct buffer_head head_table[CACHE_ENTRY_NB];
struct lock bc_lock;

void bc_init(){
   for(int i=0;i<CACHE_ENTRY_NB;i++){
      head_table[i].access=false;
      head_table[i].dirty=false;
      head_table[i].ref_bit=true;
      head_table[i].sector=-1;
   }
   clock=0;
   lock_init(&bc_lock);
}
 
void bc_flush_entry(struct buffer_head *flush_entry){
   if(flush_entry->dirty==true&&flush_entry->access==true){
      block_write(fs_device,flush_entry->sector,flush_entry->data);
   }
   flush_entry->dirty=false;
}

void bc_flush_all_entries(){
   for(int i=0;i<CACHE_ENTRY_NB;i++){
      struct buffer_head entry=head_table[i];
      if(entry.access==true){
         bc_flush_entry(&entry);
      }
   }
}

void bc_term(){
   bc_flush_all_entries();
}

struct buffer_head* bc_lookup(block_sector_t sector){
   for(int i=0;i<CACHE_ENTRY_NB;i++)
   {
     struct buffer_head *entry = &head_table[i];
     if(entry->access==true && entry->sector==sector)
       return entry;
   }
   return NULL;
}

struct buffer_head* bc_select_victim(){
   for(int j=0;j<2*CACHE_ENTRY_NB;j++)
   {
      struct buffer_head *entry=&head_table[clock];
      if(entry->access==false)
         return entry;
      if(entry->ref_bit==false){
         bc_flush_entry(entry);
         entry->access=false;
         return entry;
      }
      entry->ref_bit = false;
      clock++;
      clock%=CACHE_ENTRY_NB;
  }
}

bool bc_read (block_sector_t sector_idx, void* buffer, off_t bytes_read, int chunk_size, int sector_ofs){
   lock_acquire(&bc_lock);
   struct buffer_head* found=bc_lookup(sector_idx);
   if(found==NULL){
      found=bc_select_victim();
      found->sector=sector_idx;
      found->access=true;
      found->dirty=false;
      block_read(fs_device,sector_idx,found->data);
   }
   found->ref_bit=true;
   lock_release(&bc_lock);
   memcpy(buffer+bytes_read,found->data+sector_ofs,chunk_size);
   return true;
}

bool bc_write (block_sector_t sector_idx, void* buffer, off_t bytes_written, int chunk_size, int sector_ofs)
{
   lock_acquire(&bc_lock);
   struct buffer_head* found=bc_lookup(sector_idx);
   if(found==NULL){
     found=bc_select_victim();
     found->sector=sector_idx;
     found->access=true;
     found->dirty = false;
     block_read(fs_device,sector_idx,found->data);
   }
   found->dirty=true;
   found->ref_bit=true;
   memcpy(found->data+sector_ofs,buffer+bytes_written,chunk_size); 
   lock_release(&bc_lock);
   return true; 
}
