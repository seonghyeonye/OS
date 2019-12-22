#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <user/syscall.h>
#include <filesys/file.h>
#include <filesys/filesys.h>
#include "filesys/inode.h"
#include "filesys/fsutil.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct sppt_entry *valid_pointer(void *vaddr)
{   
  if(!(is_user_vaddr(vaddr))||(vaddr < (void *)0x08048000))
  {
     exit(-1);
  }
  struct sppt_entry *entry = find_vme(vaddr);
  if(entry==NULL){
     if(vaddr>thread_current()->esp){
        if(expand_stack(vaddr)){
           entry= find_vme(vaddr);
           entry->stk_flag=true;
        }
     }
     else{
       exit(-1);
     }
  } 
  return entry;
}

void valid_buffer(void *buffer,void* last){
    for (; buffer < last; buffer+= PGSIZE){
     struct sppt_entry* entry = valid_pointer(buffer);
     if(entry->writable==false){
       exit(-1);
     }
   }
}

void valid_write(void *str,void *end){
   for(;str<end;str+=PGSIZE){
      struct sppt_entry *entry=valid_pointer(str);
   }
}  
 
void pin_write(void* start,void* end){
   for(;start<end;start+=PGSIZE){
      struct sppt_entry *vme=find_vme(start);
      vme->ref_bit=true;
   }
}

void pin_entry(void* start,void* end){
   start=pg_round_down(start);
   for(;start<end;start+=PGSIZE){
      struct sppt_entry *vme=find_vme(start);
      if(vme->type==VM_ANON){
        if(vme->stk_flag)
          break;
        if(pagedir_get_page(thread_current()->pagedir,vme->upage)==NULL){ 
         struct frame_entry *kframe=alloc_frame_entry(PAL_USER);
         void *kpage=kframe->kpage;
         kframe->entry=vme;
         swap_in(vme->swap_slot,kpage);
         install_page(vme->upage,kpage,vme->writable);
      }
      }
      vme->ref_bit=true;
  }
}

void unpin_entry(void* start, void* end){
   for(;start<end;start+=PGSIZE){
      struct sppt_entry *vme=find_vme(start);
      vme->ref_bit=false;
  }
}

void halt(void){
  shutdown_power_off();
}

void exit (int status){
  char filename[256];
  extract_filename(thread_current()->name,filename);
  
  printf("%s: exit(%d)\n",filename,status);
  thread_current()->exit_num = status;
  thread_exit();
}

pid_t execute(const char *cmd_line){
   valid_pointer(cmd_line);
   valid_pointer(cmd_line+3);
   lock_acquire(&file_lock);
   pid_t ret = process_execute(cmd_line);
   lock_release(&file_lock);
   return ret;
}

int wait (pid_t pid){
   if(thread_current()->childone == pid)
      return -1;
   return process_wait(pid);
}

bool create(const char *file, unsigned initial_size){
  valid_pointer(file);
  lock_acquire(&file_lock);
  bool ret = filesys_create(file,initial_size);
  lock_release(&file_lock);
  return ret;
}

bool remove(const char *file){
   lock_acquire(&file_lock); 
   bool ret = filesys_remove(file);
   lock_release(&file_lock);
   return ret;
}

int open (const char *filename){
   int ret = -1;

   valid_pointer(filename);
   lock_acquire(&file_lock);

   char last_name[strlen(filename)+1];
   char file[strlen(filename)+1];
   strlcpy(file,filename,strlen(filename)+1);
   struct file* open_file = filesys_open(file);
   struct dir* cur_dir =path_find(file,last_name);

   if(open_file!=NULL)
   {
     struct inode *t;
     if(!dir_lookup(cur_dir, last_name, &t))
     {
       if(strlen(file)>1)
       {
         lock_release(&file_lock);
         return ret;
       }
     }
     
     for(int i=3;i<50;i++){
        if(thread_current()->fd[i] == NULL){
            if(strcmp(thread_current()->name,file)==0)
               file_deny_write(open_file); 
            thread_current()->fd[i]= open_file;
            ret = i;
            break;
         }
      }
   }
   lock_release(&file_lock);
   return ret;
}

int filesize(int fd){
   lock_acquire(&file_lock);
   int ret = file_length((thread_current()->fd)[fd]);
   lock_release(&file_lock);
   return ret;
}

int read(int fd, void* buffer, unsigned size){
  if(fd<0||fd>=50){
     exit(-1);
  }
  valid_buffer(buffer,buffer+size);
  lock_acquire(&file_lock);
  int ret=-1;
  if(fd==0){
    int i;
    for(i=0; i<size; i++){
       if(((char *)buffer)[i] == '\0'){
           ret=i;
           break;
       }
    }
  }
  else if(fd>2){
     struct file *file_to_read = thread_current()->fd[fd];
     pin_entry(buffer,buffer+size);
     ret = file_read(file_to_read,buffer,size);
     unpin_entry(buffer,buffer+size);
  }
  lock_release(&file_lock);
  return ret;
}


int write(int fd, const void *buffer, unsigned size){
  int ret = -1;
  if(fd<0||fd>50)
     exit(-1);
  valid_pointer(buffer);
  valid_pointer(buffer+size-1);
  lock_acquire(&file_lock);
  if(fd==1){
    putbuf(buffer,size);
    ret = size;
  }
  else if(fd>2){
    if(thread_current()->fd[fd]==NULL){
       lock_release(&file_lock);
       exit(-1);
       }
    else{
       if(inode_is_dir(file_get_inode(thread_current()->fd[fd])))
       {
         lock_release(&file_lock);
         return ret;       
       }


       pin_write(buffer,buffer+size);
       ret = file_write(thread_current()->fd[fd],buffer,size);
       unpin_entry(buffer,buffer+size);
    }
  }
  lock_release(&file_lock); 
  return ret;
}

void seek(int fd, unsigned position){
  lock_acquire(&file_lock);
  file_seek(thread_current()->fd[fd],position);
  lock_release(&file_lock);
}

unsigned tell(int fd){
  lock_acquire(&file_lock);
  int ret =file_tell(thread_current()->fd[fd]);
  lock_release(&file_lock);
  return ret;
}

void close(int fd){
  if(fd>=50||fd<0)
     exit(-1);
  if(fd>2&&fd<50){
     if(thread_current()->fd[fd]==NULL){
        exit(-1);
     }
  lock_acquire(&file_lock);
  struct file* release = thread_current()->fd[fd];
  file_allow_write(thread_current()->fd[fd]);
  file_close(thread_current()->fd[fd]);
  thread_current()->fd[fd]=NULL;
  lock_release(&file_lock);
  }
}


int mmap(int fd, void *addr){
  if(fd>=50||fd<0)
     exit(-1);
  if(pg_ofs(addr)!=0||addr==0||fd==0||fd==1){
     return -1;
  }
  struct mmap_file *mmap=(struct mmap_file*)malloc(sizeof(struct mmap_file));
  if(mmap==NULL){
     printf("malloc failed\n");
     return -1;
  }
  memset(mmap,0,sizeof(struct mmap_file));
  list_init(&mmap->vme_list);
  mmap->file=thread_current()->fd[fd];
  if(mmap->file==NULL||file_length(mmap->file)==0){
     return -1;
  }
  lock_acquire(&file_lock);
  mmap->file=file_reopen(mmap->file);
  lock_release(&file_lock);
  int mapid=0;
  struct list_elem *e;
  e=list_begin(&mmap->vme_list);  
  while(e!=list_end(&mmap->vme_list)){
     e=list_next(e);
     if(e==NULL){
        break;
     }
     mapid++;
  }   
  mmap->mapid=mapid;
  list_push_back(&thread_current()->mmap_list,&mmap->elem);
  int32_t ofs=0;
  uint32_t read_bytes = file_length(mmap->file);
  while(read_bytes>0){
     uint32_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
     uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
     if(find_vme(addr)!=NULL){
       return -1;
     }
     struct sppt_entry *vme = (struct sppt_entry *)malloc(sizeof(struct sppt_entry));
     memset(vme,0,sizeof(struct sppt_entry));
     vme->type=VM_FILE;
     vme->file=mmap->file;
     vme->offset=ofs;
     vme->upage=addr;
     vme->writable=true;
     vme->read_bytes=page_read_bytes;
     vme->zero_bytes=page_zero_bytes;
     list_push_back(&mmap->vme_list,&vme->mmap_elem);
     insert_vme(&thread_current()->vm,vme);
     read_bytes -= page_read_bytes;
     ofs+= page_read_bytes;
     addr+=PGSIZE;
  }
  thread_current()->mapid=mapid; 
  return mapid;
}

void munmap(int mapping){
  struct list_elem *e;
  struct mmap_file *file;
  for(e=list_begin(&thread_current()->mmap_list);e!=list_end(&thread_current()->mmap_list);e=list_next(e)){
     file=list_entry(e,struct mmap_file,elem);
     if(file->mapid==mapping){
         break;
     }
  }
  lock_acquire(&file_lock);
  do_munmap(file);
  lock_release(&file_lock);
}

bool isdir(int fd)
{
  if (fd>=50||fd<0)
    exit(-1);
  if (fd>2 && fd<50)
  {
    if (thread_current()->fd[fd]==NULL)
      exit(-1);
    struct file *check = thread_current()->fd[fd];
    struct inode* check_inode = file_get_inode(check);
    bool success = inode_is_dir(check_inode);
    return success;
  }
}

bool chdir(const char *dir)
{
  bool success=false;
  struct dir *cur_dir;
  char checkp[strlen(dir)+1];
  memcpy(checkp, dir, strlen(dir)+1);
  char file_name[strlen(dir)+1];

  struct dir *pdir = path_find(checkp, file_name);
  struct inode *temp_inode;
  if(!pdir)
      return false;
  if(dir_lookup(pdir, file_name, &temp_inode))
  {
      struct dir *fdir = dir_open(temp_inode);
      dir_close(thread_current()->workdir);
      thread_current()->workdir = fdir;
      success=true;
  }
  else
    success=false;
  return success;
}

bool mkdir(const char *dir)
{
  bool success=false;
  if(!strcmp(dir, "")) // empty!
    return success;

  char checkp[strlen(dir)+1];
  memcpy(checkp, dir, strlen(dir)+1);
  char file_name[strlen(dir)+1];
  char *save_ptr, *token, *next;

  struct dir *cur_dir;
  struct dir *new_dir;
  struct inode *temp_inode;
  struct dir *ndir = path_find(checkp, file_name);

  if(!dir_lookup(ndir,file_name,&temp_inode))
  {
    if(ndir!=NULL)
    {
       block_sector_t inode_sector;
       if(!free_map_allocate(1, &inode_sector))
         return false;
       dir_create(inode_sector, 16);
       bool real=dir_add(ndir,file_name, inode_sector);
       new_dir = dir_open(inode_open(inode_sector));
       dir_add(new_dir, ".", inode_sector);
       struct inode *new_i = dir_get_inode(ndir);
       dir_add(new_dir, "..", inode_get_inumber(new_i));
       dir_close(new_dir);
       success=true;
    }
  }
  dir_close(ndir);
  return success;
}

bool readdir(int fd, char *name)
{
  valid_pointer(name);
  
  if(fd>=50 || fd<3)
    exit(-1);
  else
  {
    if(thread_current()->fd[fd]==NULL)
      exit(-1);
    struct file *target = thread_current()->fd[fd];
    struct inode *load_inode=file_get_inode(target);
    if(inode_is_dir(load_inode))
    {
      struct dir *dir = dir_open(load_inode);
       
      if(dir==NULL)
        return NULL;
      if(load_inode->pos!=NULL&&load_inode->pos>=0)
        dir->pos=load_inode->pos;

      bool flag = false;
      while(!flag)
      {
        bool result = dir_readdir(dir, name);
        if(!result){
          dir_close(dir);
          return false;
        }
        else
        {
          if(strcmp(name, ".")==0 || strcmp(name, "..")==0 )
            continue;
          else
            flag=true;
        }
      }
      load_inode->pos=dir->pos;
      return flag;
    }
    else
      return false;      
  } 
}

int inumber(int fd)
{
  if(fd>=50||fd<3)
    exit(-1);
  else
  {
    if(thread_current()->fd[fd]==NULL)
      exit(-1);
    struct file *target = thread_current()->fd[fd];
    int result = inode_get_inumber(file_get_inode(target));
    return result;
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sig_num;
  valid_pointer(f->esp);
  valid_pointer(f->esp+3);
  memcpy(&sig_num,f->esp,4); 
  thread_current()->esp=f->esp;
  switch(sig_num){
    case SYS_HALT:
       halt();
       break;
     case SYS_EXIT:
       {
       int status;
       valid_pointer(f->esp+4);
       memcpy(&status,f->esp+4,sizeof(int));
       exit(status);
       break;
       }
     case SYS_EXEC:
       {
       const char *cmd_line;
       int ret;
       valid_pointer(f->esp+4);
       valid_pointer(f->esp+5);
       memcpy(&cmd_line,f->esp+4,sizeof(char*));
       ret = (int)execute(cmd_line);
       f->eax = (uint32_t)ret;
       break;
       }
     case SYS_WAIT:
       {
       pid_t pid;
       int ret;
       valid_pointer(f->esp+4);
       memcpy(&pid,f->esp+4,sizeof(pid_t));
       ret =(int)wait(pid);
       f->eax = (uint32_t)ret;
       break;
       }
     case SYS_CREATE:
       {
       const char* file;
       unsigned initial_size;
       int ret;
       valid_pointer(f->esp+4);
       valid_pointer(f->esp+8);
       memcpy(&file,f->esp+4,sizeof(char*));
       memcpy(&initial_size,f->esp+8,sizeof(unsigned));
       ret= (int)create(file,initial_size);
       f->eax = (uint32_t)ret;
       break;
       }
     case SYS_REMOVE:
       {
       const char *file;
       int ret;
       valid_pointer(f->esp+4);
       memcpy(&file,f->esp+4,sizeof(char*));
       ret = remove(file);
       f->eax = (uint32_t)ret;
       break;
       }
     case SYS_OPEN:
       {
       const char *file;
       int ret;
       valid_pointer(f->esp+4);
       memcpy(&file,f->esp+4,sizeof(char*));
       ret =open(file); 
       f->eax = (uint32_t)ret;
       break;
       }
     case SYS_FILESIZE:
       {
       int fd;
       int ret;
       valid_pointer(f->esp+4);
       memcpy(&fd,f->esp+4,sizeof(int));
       ret= filesize(fd);
       f->eax = (uint32_t)ret;
       break;
       }
     case SYS_READ:
       {
       int fd;
       int ret;
       const void* buffer;
       unsigned size;
       valid_pointer(f->esp+4);
       valid_pointer(f->esp+8);
       valid_pointer(f->esp+12);
       memcpy(&fd,f->esp+4,sizeof(int));
       memcpy(&buffer,f->esp+8,sizeof(void*));
       memcpy(&size,f->esp+12,sizeof(unsigned));
       ret = read(fd,buffer,size);
       f->eax = (uint32_t)ret;
       break;
       }
     case SYS_WRITE:
       {
       int fd, ret;
       void *buffer;
       unsigned size;
       valid_pointer(f->esp+4);
       valid_pointer(f->esp+8);
       valid_pointer(f->esp+12);       
       memcpy(&fd,f->esp+4,sizeof(int));
       memcpy(&buffer,f->esp+8,sizeof(void*));
       memcpy(&size,f->esp+12,sizeof(unsigned));
       ret = write(fd,buffer,size);
       f->eax = (uint32_t)ret;
       break; 
       }
     case SYS_SEEK:
       {
       int fd;
       unsigned position;
       valid_pointer(f->esp+4);
       valid_pointer(f->esp+8);
       memcpy(&fd,f->esp+4,sizeof(int));
       memcpy(&position,f->esp+8,sizeof(unsigned));
       seek(fd,position);
       break;
       }
     case SYS_TELL:
       {
       int fd;
       unsigned ret;
       valid_pointer(f->esp+4);
       memcpy(&fd,f->esp+4,sizeof(int));
       ret = tell(fd);
       f->eax = (uint32_t)ret;
       break;
       } 
     case SYS_CLOSE:
       {
       int fd;
       valid_pointer(f->esp+4);
       memcpy(&fd,f->esp+4,sizeof(int));
       close(fd);
       break;
       }
     case SYS_MMAP:
       {
       int fd,ret;
       void *addr;
       valid_pointer(f->esp+4);
       valid_pointer(f->esp+8);
       memcpy(&fd,f->esp+4,sizeof(int));
       memcpy(&addr,f->esp+8,sizeof(void*));
       ret = mmap(fd,addr);
       f->eax= (uint32_t)ret;
       break;
       }
     case SYS_MUNMAP:
       {
       int mapping;
       valid_pointer(f->esp+4);
       memcpy(&mapping,f->esp+4,sizeof(int));
       munmap(mapping);
       break;
       }

// Pintos Project 4
     case SYS_CHDIR:
       {
       int ret;
       const char *dir;
       valid_pointer(f->esp+4);
       memcpy(&dir, f->esp+4, sizeof(char*));
       ret = chdir(dir);
       f->eax = (int)ret;       
       break;
       }
     case SYS_MKDIR:
       {
       int ret;
       const char *dir;
       valid_pointer(f->esp+4);
       memcpy(&dir, f->esp+4, sizeof(char*));
       ret = mkdir(dir);
       f->eax = (int)ret;
       break;
       }
     case SYS_READDIR:
       {
       int ret, fd;
       char *name;
       valid_pointer(f->esp+4);
       valid_pointer(f->esp+8);
       memcpy(&fd, f->esp+4, sizeof(int));
       memcpy(&name, f->esp+8, sizeof(char*));
       ret = readdir(fd, name);
       f->eax = (int)ret;
       break;
       }
     case SYS_ISDIR:
       {
       int fd, ret;
       valid_pointer(f->esp+4);
       memcpy(&fd, f->esp+4,sizeof(int));
       ret = isdir(fd);
       f->eax = (int)ret;
       break;
       }
     case SYS_INUMBER:
       {
       int fd, ret;
       valid_pointer(f->esp+4);
       memcpy(&fd, f->esp+4, sizeof(int));
       ret = inumber(fd);
       f->eax = (int)ret;
       break;
       }
   }
}
