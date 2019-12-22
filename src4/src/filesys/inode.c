#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCK_ENTRIES 123
#define INDIRECT_BLOCK_ENTRIES 128


enum direct_t
  {
    DIRECT,
    INDIRECT,
    DOUBLE_INDIRECT,
    OUT_LIMIT
  };

struct sector_location
  {
    int directness;
    int index1;
    int index2;
  };

struct inode_indirect_block
  {
    block_sector_t map_table[INDIRECT_BLOCK_ENTRIES];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}


static bool get_disk_inode(const struct inode *inode,struct inode_disk *inode_disk){
    bool success=bc_read(inode->sector,inode_disk,0,BLOCK_SECTOR_SIZE,0);
    return success;
}

static void locate_byte(off_t pos,struct sector_location *sec_loc){
   off_t pos_sector=pos/BLOCK_SECTOR_SIZE;
   if(pos_sector<DIRECT_BLOCK_ENTRIES){
      sec_loc->directness=DIRECT;
      sec_loc->index1=pos_sector;
      sec_loc->index2=0;
   }
   else if(pos_sector<DIRECT_BLOCK_ENTRIES+INDIRECT_BLOCK_ENTRIES){
      pos_sector-=DIRECT_BLOCK_ENTRIES;
      sec_loc->directness=INDIRECT;
      sec_loc->index1=pos_sector;
      sec_loc->index2=0;
   }
   else if(pos_sector<DIRECT_BLOCK_ENTRIES+INDIRECT_BLOCK_ENTRIES*(INDIRECT_BLOCK_ENTRIES+1)){
      pos_sector-=DIRECT_BLOCK_ENTRIES+INDIRECT_BLOCK_ENTRIES;
      sec_loc->directness=DOUBLE_INDIRECT;
      sec_loc->index1=pos_sector/INDIRECT_BLOCK_ENTRIES;
      sec_loc->index2=pos_sector%INDIRECT_BLOCK_ENTRIES;   
   }
   else{
    sec_loc->directness=OUT_LIMIT;
  }
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (struct inode_disk *disk, off_t pos) 
{
  block_sector_t result;
  
  if (pos < disk->length){
    struct sector_location sec_loc;
    struct inode_indirect_block indirect,indirect2;
    locate_byte(pos,&sec_loc);
    switch(sec_loc.directness){
        case DIRECT:
           result=disk->direct_map_table[sec_loc.index1];
           break;
        case INDIRECT:
           if(disk->indirect_block==NULL)
              return -1;
           bc_read(disk->indirect_block,&indirect,0,BLOCK_SECTOR_SIZE,0); 
           result=indirect.map_table[sec_loc.index1];
           break;
        case DOUBLE_INDIRECT:
           if(disk->double_block==NULL){
              return -1;
           }
           bc_read(disk->double_block,&indirect,0,BLOCK_SECTOR_SIZE,0);
           if(indirect.map_table[sec_loc.index1]==-1){
              return -1;
           }
           bc_read(indirect.map_table[sec_loc.index1],&indirect2,0,BLOCK_SECTOR_SIZE,0);
           result=indirect2.map_table[sec_loc.index2]; 
           break;
        case OUT_LIMIT:
           return -1; 
    } 
    return result;
  }
  else{
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

void
update_direct(struct inode_disk* disk_inode, size_t length, char* zeros){
  for(int j=0;j<length;j+=BLOCK_SECTOR_SIZE){
      int i=j/BLOCK_SECTOR_SIZE;
      block_sector_t *block=&disk_inode->direct_map_table[i];
      if(*block==NULL){
         free_map_allocate(1,block);
         bc_write(*block,zeros,0,BLOCK_SECTOR_SIZE,0);
      }
  }
}  

void
update_indirect(struct inode_disk* disk_inode,size_t length,char* zeros){
  block_sector_t sector;
  block_sector_t *block=&disk_inode->indirect_block;
  struct inode_indirect_block indirect;
  for(int j=0;j<length;j+=BLOCK_SECTOR_SIZE){
     int i=j/BLOCK_SECTOR_SIZE;
     sector = byte_to_sector(disk_inode,j+512*123);
     if(sector!=-1)
        continue;
     free_map_allocate(1,&sector);
     if(*block==NULL){
        free_map_allocate(1,block);
        memset(&indirect,-1,BLOCK_SECTOR_SIZE);
     }
     else{
     bc_read(*block,&indirect,0,BLOCK_SECTOR_SIZE,0);
     }
     if(indirect.map_table[i]==-1){
        indirect.map_table[i]=sector;
     }
     bc_write(*block,&indirect,0,BLOCK_SECTOR_SIZE,0);
     bc_write(sector,zeros,0,BLOCK_SECTOR_SIZE,0);
  }  
}

void
update_double(struct inode_disk* disk_inode,size_t length,char* zeros){
  struct inode_indirect_block indirect0,indirect2;
  struct sector_location sec_loc2;
  block_sector_t *block=&disk_inode->double_block;
  bool flag=0;
  for(int j=0;j<length;j+=BLOCK_SECTOR_SIZE){
      block_sector_t sector =byte_to_sector(disk_inode,j+512*251);
      if(sector!=-1)
         continue;
      free_map_allocate(1,&sector);
      if(*block==NULL){
         free_map_allocate(1,block);
         memset(&indirect0,-1,BLOCK_SECTOR_SIZE);
      }
      else{
         bc_read(*block,&indirect0,0,BLOCK_SECTOR_SIZE,0);
      }
      locate_byte(j+512*251,&sec_loc2);
      block_sector_t *sector2=&indirect0.map_table[sec_loc2.index1];
      if(*sector2==-1){
         flag=1;
         free_map_allocate(1,sector2);
         memset(&indirect2,-1,BLOCK_SECTOR_SIZE);
      }
      else{
         bc_read(*sector2,&indirect2,0,BLOCK_SECTOR_SIZE,0);
      }
      if(indirect2.map_table[sec_loc2.index2]==-1){
         indirect2.map_table[sec_loc2.index2]=sector;
      }
      if(flag){
         bc_write(disk_inode->double_block,&indirect0,0,BLOCK_SECTOR_SIZE,0);
      }
      bc_write(*sector2,&indirect2,0,BLOCK_SECTOR_SIZE,0);
      bc_write(sector,zeros,0,BLOCK_SECTOR_SIZE,0);
  }
}

bool
update_length(struct inode_disk* disk_inode, size_t length)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  struct sector_location sec_loc;
  size_t newlength=length;
  if(newlength!=0)
     newlength=length-1;
  locate_byte(newlength,&sec_loc);
  int direct=sec_loc.directness;
  switch(direct){
      case DIRECT:
         update_direct(disk_inode,length,zeros);
         break;
      case INDIRECT:
         update_direct(disk_inode,BLOCK_SECTOR_SIZE*DIRECT_BLOCK_ENTRIES,zeros);
         length-=BLOCK_SECTOR_SIZE*DIRECT_BLOCK_ENTRIES;
         update_indirect(disk_inode,length,zeros);
         break;
      case DOUBLE_INDIRECT:
         update_direct(disk_inode,BLOCK_SECTOR_SIZE*DIRECT_BLOCK_ENTRIES,zeros);
         length-=BLOCK_SECTOR_SIZE*DIRECT_BLOCK_ENTRIES;
         update_indirect(disk_inode,BLOCK_SECTOR_SIZE*INDIRECT_BLOCK_ENTRIES,zeros);
         length-=BLOCK_SECTOR_SIZE*INDIRECT_BLOCK_ENTRIES;
         update_double(disk_inode,length,zeros);
         break;
  }
  return true;
}

void free_direct_table(struct inode_disk disk){
  for(int i=0;i<DIRECT_BLOCK_ENTRIES;i++){
     block_sector_t block =disk.direct_map_table[i];
     if(block!=NULL){
        free_map_release(disk.direct_map_table[i],1);
     }
     else{
       return;
     }
  }
}

void free_indirect_table(block_sector_t sector){
  struct inode_indirect_block indirect;
  bc_read(sector,&indirect,0,BLOCK_SECTOR_SIZE,0);
  
  for(int i=0;i<INDIRECT_BLOCK_ENTRIES;i++){
     if(indirect.map_table[i]!=NULL){
        free_map_release(indirect.map_table[i],1);
     }
     else{
       return;
     }
  }
}

void free_sector(struct inode_disk disk){
  free_direct_table(disk);
  if(disk.indirect_block==NULL)
     return;
  struct inode_indirect_block *indirect2;
  free_indirect_table(disk.indirect_block);
  free_map_release(disk.indirect_block,1); 
  if(disk.double_block==NULL)
     return;
  bc_read(disk.double_block,indirect2,0,BLOCK_SECTOR_SIZE,0);
  for(int j=0;j<INDIRECT_BLOCK_ENTRIES;j++){
     if(indirect2->map_table[j]!=NULL){
       free_indirect_table(indirect2->map_table[j]);
       free_map_release(indirect2->map_table[j],1);
     }
     else{
       break;
     }
  }
  free_map_release(disk.double_block,1);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, uint32_t is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->is_dir = is_dir;
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      /*if (free_map_allocate (sectors, &disk_inode->start)) 
        {
          block_write (fs_device, sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                block_write (fs_device, disk_inode->start + i, zeros);
            }
          success = true; 
        } 
      free (disk_inode);*/
      update_length(disk_inode,length);
      bc_write(sector,disk_inode,0,BLOCK_SECTOR_SIZE,0);
      free(disk_inode);
      success=true;
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->extend_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          struct inode_disk disk; 
          bc_read(inode->sector,&disk,0,BLOCK_SECTOR_SIZE,0);
          free_sector(disk);
          free_map_release (inode->sector, 1);
        }
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  struct inode_disk disk_inode;
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  lock_acquire(&inode->extend_lock);
  bc_read(inode->sector,&disk_inode,0,BLOCK_SECTOR_SIZE,0);
  while (size > 0) 
    {
      block_sector_t sector_idx = byte_to_sector (&disk_inode, offset);
      if(sector_idx==-1){
         break;
      }
      lock_release(&inode->extend_lock);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      off_t inode_left = disk_inode.length - offset; //inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0){
        lock_acquire(&inode->extend_lock);
        break;
      }
      /*if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          //block_read (fs_device, sector_idx, buffer + bytes_read);
          //printf("pass read\n");
          bc_read(sector_idx,buffer,bytes_read,chunk_size,sector_ofs);
        }
      else 
        {
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }*/
      bc_read(sector_idx,buffer,bytes_read,chunk_size,sector_ofs);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
      lock_acquire(&inode->extend_lock);
    }
  lock_release(&inode->extend_lock);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  struct inode_disk disk_inode;
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;
  lock_acquire(&inode->extend_lock);
  bc_read(inode->sector,&disk_inode,0,BLOCK_SECTOR_SIZE,0); 
  if(offset+size>disk_inode.length){
     disk_inode.length=offset+size;
     update_length(&disk_inode,offset+size);
     bc_write(inode->sector,&disk_inode,0,BLOCK_SECTOR_SIZE,0);
  }
  
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&disk_inode, offset);
      lock_release(&inode->extend_lock);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      off_t inode_left = disk_inode.length-offset;//inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;
      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0){
        lock_acquire(&inode->extend_lock);
        break;
      }

      /*if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
         // printf("pass write\n");
         // block_write (fs_device, sector_idx, buffer + bytes_written);
          bc_write(sector_idx,buffer,bytes_written,chunk_size,sector_ofs);
         // printf("write finish\n");
        }
      else 
        {
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }*/
          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          /*if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
            //bc_read(sector_idx,bounce,0,512,0);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }*/
      bc_write(sector_idx,buffer,bytes_written,chunk_size,sector_ofs);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
      lock_acquire(&inode->extend_lock);
  }
  lock_release(&inode->extend_lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  //printf("deny wirte is %d\n",inode->deny_write_cnt);
  //printf("inode open is %d\n",inode->open_cnt);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk disk;
  bc_read(inode->sector,&disk,0,BLOCK_SECTOR_SIZE,0);
  return disk.length;
}

bool inode_is_dir (const struct inode * inode)
{
  bool result;
  struct inode_disk *disk_inode;

  disk_inode = malloc(sizeof(struct inode_disk));
  get_disk_inode(inode, disk_inode);
  if(disk_inode->is_dir == 1)
    result = true;
  else
    result = false;
  free(disk_inode);
  return result;
}

