#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/fsutil.h"
/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
struct dir* path_find(char*, char*);
char* get_file_name (const char*);
struct dir* new_path(const char*);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");
  inode_init ();
  free_map_init ();
  bc_init();
  if (format) 
    do_format ();

  free_map_open ();
  thread_current()->workdir =dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  bc_term();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  char rename[strlen(name)+1];
  strlcpy(rename, name, strlen(name)+1);

  char file_name[strlen(name)+1];
  struct dir *new_dir = path_find(rename,file_name);

  if(dir_get_inode(new_dir)->removed)
     return false;

  bool success = (new_dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, 0)
                  && dir_add (new_dir, file_name, inode_sector));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (new_dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  char rename[strlen(name)+1];
  strlcpy(rename, name, strlen(name)+1);

  char file_name[strlen(name)+1];
  struct dir *new_dir = path_find(rename, file_name);
  
  struct inode *inode = NULL;

  if (new_dir != NULL)
  {
    if(!dir_lookup (new_dir, file_name, &inode))
      return NULL;
  }
  else
    return NULL;

  if(inode->removed||dir_get_inode(new_dir)->removed)
    return NULL;

  dir_close (new_dir);
  return file_open (inode);
}


/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  char file_name[strlen(name)+1];
  struct dir *chdir = path_find(name,file_name);

  bool result = false;
  struct inode *temp_inode = NULL;
  struct inode_disk disk;
  if(strcmp(file_name, "")==0)
  {
    dir_close(chdir);
    return result;
  }
  if(dir_lookup(chdir, file_name, &temp_inode))
  {
    if(inode_is_dir(temp_inode))
    {
      struct dir *indir = dir_open(temp_inode);
      char elemname[NAME_MAX+1];
      bool flag = false;
      while(!flag)
      {
        if(dir_readdir(indir, elemname))
        {
          if(elemname != NULL){
	    if(strcmp(elemname, ".")==0 || strcmp(elemname, "..")==0)
              continue;
            else
              break;
          }
          else
            break;
        }
        else
          flag = true;
      }
      if(flag)
        result = chdir != NULL && dir_remove(chdir, file_name);

      dir_close(indir);
      dir_close(chdir);
      return result;
    }
    else // It is a file
    {
      result = chdir != NULL && dir_remove(chdir, file_name);
      dir_close(chdir);
      return result;
    }
  }
  else // Name is wrong
  {
    dir_close(chdir);
    return result;
  }
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  struct dir *new_dir = dir_open_root();

  dir_add(new_dir, ".", ROOT_DIR_SECTOR);
  dir_add(new_dir, "..", ROOT_DIR_SECTOR);  
  free_map_close ();
  printf ("done.\n");
}

struct dir* path_find (char *path_name, char *file_name)
{
  size_t length=strlen(path_name)+1;
  if(length==1)
    return NULL;

  char temp[length];
  strlcpy(temp,path_name,length);
  struct inode *temp_inode;
  char *save_ptr,*token,*next;
  bool is_abs = (temp[0] == '/'); 

  struct dir *cur_dir;
  if (is_abs)  // If the path is absolute, start with open root
    cur_dir = dir_open_root();
  else
    cur_dir = dir_reopen(thread_current()->workdir);
  
  token=strtok_r(temp,"/",&save_ptr);
  next=strtok_r(NULL,"/",&save_ptr);
  if(token==NULL)
  {
    strlcpy(file_name,".",length);
    return cur_dir;
  }

    while(token!=NULL&&next!=NULL){
       if(dir_lookup(cur_dir,token,&temp_inode)){
          if(inode_is_dir(temp_inode)){
             strlcpy(file_name,token,length);
             dir_close(cur_dir);
             cur_dir=dir_open(temp_inode);
             
             token=next;
             next=strtok_r(NULL,"/",&save_ptr);
             continue;
          }
          dir_close(cur_dir);
          return NULL;
       }
       dir_close(cur_dir);
       return NULL;
    }
    strlcpy(file_name,token,length);
    return cur_dir;
}

char* get_file_name (const char* path)
{
  char *temp_path = malloc(strlen(path)+1);
  memcpy(temp_path, path, strlen(path)+1);

  char *token, *save_ptr, *prev_token = "";
  for(token = strtok_r(temp_path, "/", &save_ptr); token!=NULL;
      token = strtok_r(NULL, "/", &save_ptr))
  {
    prev_token = token;
  }
  char *file_name = malloc(strlen(prev_token)+1);
  memcpy(file_name, prev_token, strlen(prev_token)+1);
  return file_name;
}

struct dir* new_path(const char* path)
{
  // This function goes just before the last
  char *temp = malloc(strlen(path)+1);
  memcpy(temp, path, strlen(path)+1);
  
  char *token, *save_ptr;
  char *ntoke=NULL;
  struct dir *cur_dir;
  struct inode *check_inode;
  if(thread_current()->workdir == NULL || *path == '/')
  {
    cur_dir = dir_open_root();
  }
  else
  {
    cur_dir = dir_reopen(thread_current()->workdir);
  }
  token = strtok_r(temp, "/", &save_ptr);
  if(token)
    ntoke = strtok_r(NULL, "/", &save_ptr);
  while(ntoke!=NULL)
  {
    if(strcmp(token, ".")==0)
    {
      token = ntoke;
      ntoke = strtok_r(NULL, "/", &save_ptr);
      continue;
    }
    else if(strcmp(token, "..")==0)
    {
      if(!dir_lookup(cur_dir, token, &check_inode))
        printf("Why there is no ..\n");
      dir_close(cur_dir);
      cur_dir = dir_open(check_inode);
    }
    else
    {
      if(dir_lookup(cur_dir, token, &check_inode))
      {
        if(inode_is_dir(check_inode))
        {
          dir_close(cur_dir);
          cur_dir = dir_open(check_inode);
        }
        else
          return NULL;
      }
      else
        return NULL;
    }
    // For next loop
    token = ntoke;
    ntoke = strtok_r(NULL, "/", &save_ptr);
  }
  return cur_dir;
}
