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
#include "threads/synch.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

struct lock file_lock;
//struct semaphore exit_sema;

void
syscall_init (void)
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void valid_pointer(void *vaddr)
{   
  if(!(is_user_vaddr(vaddr))||(vaddr < (void *)0x08048000)||!(pagedir_get_page(thread_current()->pagedir, vaddr)))
     {
     exit(-1);
  }
}

void halt(void){
  shutdown_power_off();
}

void exit (int status){
  char filename[256];
  extract_filename(thread_current()->name,filename);
  for(int i=3;i<50;i++){
     if(thread_current()->fd[i] != NULL){
        close(i);
    }
  }
  
  printf("%s: exit(%d)\n",filename,status);
  thread_current()->exit_num = status;
  
  thread_exit();
}

pid_t execute(const char *cmd_line){
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
  bool ret = filesys_create(file,initial_size);
  return ret;
}

bool remove(const char *file){
   
   bool ret = filesys_remove(file);
   return ret;
}

int open (const char *file){
   int ret = -1;
   valid_pointer(file);
   lock_acquire(&file_lock);
   struct file* open_file =filesys_open(file);
   if(open_file!=NULL){
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
  valid_pointer(buffer);
  int ret=-1;
  lock_acquire(&file_lock);
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
     ret = file_read(file_to_read,buffer,size);
  }
  lock_release(&file_lock);
  return ret;
}


int write(int fd, const void *buffer, unsigned size){
  int ret = -1;
  valid_pointer(buffer);
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
    ret = file_write(thread_current()->fd[fd],buffer,size);
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
  struct file* release = thread_current()->fd[fd];
  lock_acquire(&file_lock);
  file_allow_write(thread_current()->fd[fd]);
  file_close(thread_current()->fd[fd]);
  thread_current()->fd[fd]=NULL;
  //list_remove(&release->child);
  lock_release(&file_lock);
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sig_num;
  valid_pointer(f->esp);
  //valid_pointer(f->esp+3);
  memcpy(&sig_num,f->esp,4); 
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
       valid_pointer(f->esp+4);
       memcpy(&file,f->esp+4,sizeof(char*));
       remove(file);
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
   }
}
