#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "filesys/off_t.h"

struct buffer_head{
   //struct inode* inode;
   bool dirty;
   block_sector_t sector;
   bool ref_bit;
   //void* data;
   char data[BLOCK_SECTOR_SIZE];
   struct lock buf_lock;
   bool access;
};

void bc_init();
void bc_flush_entry(struct buffer_head *flush_entry);
void bc_flush_all_entries();
void bc_term();
struct buffer_head* bc_lookup(block_sector_t sector);
struct buffer_head* bc_select_victim();
bool bc_read (block_sector_t sector_idx, void* buffer, off_t bytes_read, int chunk_size, int sector_ofs);
bool bc_write (block_sector_t sector_idx, void* buffer, off_t bytes_written, int chunk_size, int sector_ofs);
 
#endif
