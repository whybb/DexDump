
/*
 * 
 * file: Drodex.h
 *
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>// open / O_RDONLY
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>// errno
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
//#include <linux/user.h>

static const char* odex_magic = "dey\n036";
static const char* dex_magic = "dex\n035";
static const char* static_safe_location = "/data/local/tmp/dump/";
static const char* odex_suffix = ".dumped_odex";
static const char* dex_suffix = ".dumped_dex";

typedef struct 
{
  uint32_t start;
  uint32_t end;
} memory_region;////dump memory_region

uint32_t get_clone_pid(uint32_t service_pid);
uint32_t get_process_pid(const char* target_package_name);
char *determine_filter(uint32_t clone_pid, int memory_fd);
int find_dex_magic_memory(uint32_t clone_pid, int memory_fd, memory_region *memory,const char *file_name);
int peek_memory(int memory_file, uint32_t address);
int dump_memory_dex(const char *buffer , int len , char each_filename[]);
int attach_get_memory(uint32_t pid);

