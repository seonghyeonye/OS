#include <bitmap.h>
#include <debug.h>
#include "vm/swap.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static struct block *block;
static struct bitmap *swap_bit;
static struct lock swap_lock;

void swap_init(){
  block = block_get_role(BLOCK_SWAP);
  swap_bit = bitmap_create(1024);//2^22/2^12
}

void swap_in(size_t used_index, void* kaddr){
  if(bitmap_test(swap_bit,used_index)==false)
    PANIC("swap in failed.");

  for(int i=0;i<8;i++){
    block_read(block,used_index*8+i,kaddr+512*i);
  }  
  bitmap_set(swap_bit,used_index,false);
}

size_t swap_out(void* kaddr){
  size_t out_index = bitmap_scan(swap_bit,0,1,false);
  for(int i=0;i<8;i++){
     block_write(block,out_index*8+i,kaddr+(512*i));
  }
  bitmap_set(swap_bit,out_index,true);
  return out_index;
}
