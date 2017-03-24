//
// Created by Wei on 2016/12/18.
//
#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "Dex.h"
#include "Drodex.h"
#define TAG    "native"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)

JNIEXPORT jint JNICALL
               Java_com_example_wings_dexdump_NativeTool_DumpDex(JNIEnv *env, jclass type, jstring name_)
{
    const char *name = (*env)->GetStringUTFChars(env,name_, 0);

    //Check root
   /* if(getuid() != 0)
    {
       // printf("[!error!]  This Device Not root! quitting\n");
        LOGD("[!error!]  This Device Not root! quitting");
        return -1;m,
    }*/

    int result=1;
    LOGD(" pakage name is : %s",name);

    printf("[*correct*]  Try to Hunting for %s  \n", name);

    LOGD("[*correct*]  Try to Hunting for %s ", name);



    int wait_times=0.1;
    // int count =0; count for the loop
    /*
     * Into the loop
     */

    //int count=0;//do the count

    while(1)
    {
        //wait some time
        sleep(wait_times);
        uint32_t pid = -1;
        // 1st----get the process pid
        pid = get_process_pid(name);

        //find process
        if(pid < 1 || pid == -1)
        {
            LOGD("[!error!] Process %s could not be found! \n ",name);
            printf("[!error!] Process %s could not be found! \n ",name);
            //continue;
            return -1;
        }

        LOGD("[##1st step ----done##] the Service pid is ----- %d", pid);
        printf("[##1st step ----done##] the Service pid is ----- %d\n", pid);

        //find cloned process
        uint32_t clone_pid = get_clone_pid(pid);
        if(clone_pid <= 0)
        {
            LOGD("[!error!] A suitable clone process could not be found!");
            printf("[!error!] A suitable clone process could not be found! \n");
            continue;
            //return -1;
        }


        LOGD("[##2nd step ----done##]  the clone pid is ----- %d", clone_pid);
        printf("[##2nd step ----done##]  the clone pid is ----- %d\n", clone_pid);


        memory_region memory;
        //ptrace cloned process
        LOGD("[*log*]  ptrace [clone_pid] %d", clone_pid);
        printf("[*log*]  ptrace [clone_pid] %d\n", clone_pid);

        int mem_file = attach_get_memory(clone_pid);

        LOGD("[*log*] the men_file is %d", 	mem_file);
        printf("[*log*] the men_file is %d\n", 	mem_file );

        //	count=count+1；//do 5 times

        if(mem_file == -1001)
        {
            LOGD("[!error!] An error occurred attaching and finding the memory!");
            printf("[!error!] An error occurred attaching and finding the memory!\n");
            continue;

        }
        else if(mem_file == -2002)
        {
            LOGD("[!error!]the process has been tracked or cannot be tracked!");
            printf("[!error!]the process has been tracked or cannot be tracked!\n");
            //continue;
        }
        else if(mem_file == -3003)
        {
            LOGD("[!error!]open error!");
            printf("[!error!]open error!\n"); //open error
            //continue;
        }

        LOGD("[##3rd step ----done##]   ptrace attach to the  %d", clone_pid);
        printf("[##3rd step ----done##]   ptrace attach to the  %d\n", clone_pid);


        // Build a safe file to dump to and call the memory dumping function--this is for dex dump
        char *dumped_file_name = malloc(strlen(static_safe_location) + strlen(name) + strlen(dex_suffix));
        sprintf(dumped_file_name, "%s%s%s", static_safe_location, name, dex_suffix);//dump ---dex

        LOGD("[*log*]  Looking for dex magic ...");
        printf("[*log*]  Looking for dex magic ...\n");

        if(find_dex_magic_memory(clone_pid, mem_file, &memory, dumped_file_name) <= 0)
        {
            LOGD("[*log*]  The dex magic was Not Found!");
            printf("[*log*]  The dex magic was Not Found!\n");

            ptrace(PTRACE_DETACH, clone_pid, NULL, 0);
            close(mem_file);
            continue;
            //return -1;
        }
        else
        {
            /*
             * Successed & exit
             */
            LOGD("[##4th step ----done##]   dex have been dumped");
            printf("[##4th step ----done##]   dex have been dumped\n");
            close(mem_file);
            ptrace(PTRACE_DETACH, clone_pid, NULL, 0);
            break;
        }
    }

    LOGD("[*log*]  All thing Done.");
    printf("[*log*]  All thing Done.\n\n");
    return 1;

    // TODO
    return result;
    //env->ReleaseStringUTFChars(name_, name);
}


/*
 * Using a known package name, recurse through the /proc/pid
 * directory and look at the cmdline for the package name, this
 * should give us the "parent" pid for any package we are looking
 * for, which is then referenced as "service_id"
 */

uint32_t get_process_pid(const char *target_package_name)
{
    char self_pid[10];
    sprintf(self_pid, "%u", getpid());

    //  printf("[*]  the pid is%d...\n",getpid());  //this getpid() is just Drodex  pid

    LOGD("[*]  the pid is%d...",getpid());

    DIR *proc = NULL;
    //Open path-- /proc
    if((proc = opendir("/proc")) == NULL)
    {
        LOGD("can not open the dir");
        return -1;
    }
    struct dirent *directory_entry = NULL;
    //Each cycle  read file path of the folder
    while((directory_entry = readdir(proc)) != NULL)
    {

        if (directory_entry == NULL)
            return -1;

        // We don't care if it's self or our own pid
        if (strcmp(directory_entry->d_name, "self") == 0 || strcmp(directory_entry->d_name, self_pid) == 0)
            continue;

        char cmdline[1024];
        //path of the file to read the ,open the road /proc/pid/cmdline
        snprintf(cmdline, sizeof(cmdline), "/proc/%s/cmdline", directory_entry->d_name);
        FILE *cmdline_file = NULL;
        // Attempt to iterate to next one if failed...
        if((cmdline_file = fopen(cmdline, "r")) == NULL)
            continue;

        char process_name[1024];
        fscanf(cmdline_file, "%s", process_name);
        fclose(cmdline_file);

        //LOGD("the cmdline_file is %s",cmdline_file);//log the read list

        if(strcmp(process_name, target_package_name) == 0)
        {
            closedir(proc);
            //log for the pid if we find
            printf("[*log*] Process %s PID:  %s\n", target_package_name,directory_entry->d_name);
            return atoi(directory_entry->d_name);
        }
    }

    closedir(proc);
    return -1;
}




/*
 * Since most of these tools provide "anti-debugging" features using ptrace,
 * we are going to take advantage of the Android app lifecycle and just steal
 * the memory form a cloned process which is never ptraced.
 *
 * This function will simply recurse through the given pids /proc/pid/task/
 * directory and collect the last one, which has always worked in tests done.
 */

uint32_t get_clone_pid(uint32_t service_pid)
{
    DIR *service_pid_dir;
    char service_pid_directory[1024];
    sprintf(service_pid_directory, "/proc/%d/task/", service_pid);

    if((service_pid_dir = opendir(service_pid_directory)) == NULL)
    {
        return -1;
    }

    struct dirent* directory_entry = NULL;
    struct dirent* last_entry = NULL;

    while((directory_entry = readdir(service_pid_dir)) != NULL)
    {
        last_entry = directory_entry;
    }

    if(last_entry == NULL)
        return -1;

    closedir(service_pid_dir);

    return atoi(last_entry->d_name);
}



// Perform all that ptrace magic
int attach_get_memory(uint32_t pid)
{
    char mem[1024];
    bzero(mem,1024);
    snprintf(mem, sizeof(mem), "/proc/%d/mem", pid);

    // Attach to process so we can peek/dump
    int ret = -1;
    ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    int mem_file;

    if (0 != ret)
    {
        int err = errno;	//get the errno
        if(err == 1) //EPERM
        {
            return -1001;	//Represents the process has been tracked or cannot be tracked
        }
        else
        {
            return -2002;	//Other errors (process does not exist or illegal operation)
        }
    }
    else
    {
        //Get the mem file so we can read when we want too
        if(!(mem_file = open(mem, O_RDONLY)))
        {
            return -3003;  	//open error
        }
    }
    return mem_file;
}

/*
 * Find the "magic" memory location we want, usually an dex so we are currently
 * recursing through the /proc/pid/maps and use lseek64 and  read at memory locations using
 * the dump_memory function.
 */

int find_dex_magic_memory(uint32_t clone_pid, int memory_fd, memory_region *memory ,const char *file_name)
{
    int ret = 0;
    char maps[2048];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", clone_pid);

    FILE *maps_file = NULL;
    if((maps_file = fopen(maps, "r")) == NULL)
    {
        LOGD("[!error!]fopen %s Error" , maps);
        printf("[!error!]fopen %s Error  \n" , maps);
        return -1;
    }

    // Scan the /proc/pid/maps file and find possible memory of interest
    char mem_line[1024];
    while(fscanf(maps_file, "%[^\n]\n", mem_line) >= 0)
    {
        char mem_address_start[10]={0};
        char mem_address_end[10]={0};
        char mem_info[1024]={0};

        LOGD("[*log*]meminfo: %s ",mem_line);

        sscanf(mem_line, "%8[^-]-%8[^ ]%*s%*s%*s%*s%s", mem_address_start, mem_address_end,mem_info);
        memset(mem_line , 0 ,1024);
        uint32_t mem_start = strtoul(mem_address_start, NULL, 16);
        memory->start = mem_start;
        memory->end = strtoul(mem_address_end, NULL, 16);

        //get the memory length
        int len =  memory->end - memory->start;

        if(len <= 10000)
        {//too small

            continue;
        }
        else if(len >= 150000000)
        {//too big
            continue;
        }

        char each_filename[254] = {0};
        char randstr[10] = {0};
        //Generate a random number, in order to facilitate the naming
        sprintf(randstr ,"%d", rand()%99 );

        strncpy(each_filename , file_name , 200);
        strncat(each_filename , randstr , 10);
        strncat(each_filename , ".dex" , 4);

        // insurance, first zero,
        lseek64(memory_fd , 0 , SEEK_SET);
        off_t r1 = lseek64(memory_fd , memory->start , SEEK_SET);
        if(r1 == -1)
        {
            continue;
            printf("[!error!---] off_t do not exit\n");
            //do nothing

        }
        else
        {
            char *buffer = malloc(len);
            ssize_t readlen = read(memory_fd, buffer, len);
            //printf("[*log*]meminfo: %s ,len: %d ,readlen: %d, start: %x\n",mem_info, len, readlen, memory->start);
             //LOGD("[*log*]meminfo: %s ,len: %d ,readlen: %d, start: %x",mem_info, len, readlen, memory->start);
            //meet the so,free it ---elf ----the so file magic is elf
            if(buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F')
            {
                free(buffer);

                continue;
            }
            if(buffer[0] == 'd' && buffer[1] == 'e' && buffer[2] == 'x' && buffer[3] == '\n'  && buffer[4] == '0' && buffer[5] == '3')
            {
                LOGD("[*log*]meminfo: %s ,len: %d ,readlen: %d, start: %x",mem_info, len, readlen, memory->start);
                LOGD("[*log*] find dex----- len : %d , info : %s" , readlen , mem_info);

                printf("[*log*]meminfo: %s ,len: %d ,readlen: %d, start: %x\n",mem_info, len, readlen, memory->start);
                printf("[*log*] find dex----- len : %d , info : %s\n" , readlen , mem_info);
                DexHeader header;
                char real_lenstr[10]={0};
                memcpy(&header , buffer ,sizeof(DexHeader));
                sprintf(real_lenstr , "%x" , header.fileSize);
                //use the Dexhead struct to confirm the length
                long real_lennum = strtol(real_lenstr , NULL, 16);

                LOGD("[*log*] This dex's fileSize: %ld", real_lennum);
                printf("[*log*] This dex's fileSize: %ld\n", real_lennum);


                if(dump_memory_dex(buffer , len , each_filename)  == 1)
                {
                    LOGD("[*log*] dex dump into %s", each_filename);
                    printf("[*log*] dex dump into %s\n", each_filename);
                    free(buffer);
                    //this use continue or return? we can try
                    //this we use continue---we should dump all dex because we do not kniw which dex is our main dex
                    continue;
                    //return 1;
                }
                else
                {
                    LOGD("[!error!] dex dump error");
                    printf("[!error!] dex dump error \n");
                }

            }
            free(buffer);
        }


        lseek64(memory_fd , 0 , SEEK_SET);

        r1 = lseek64(memory_fd , memory->start + 8 , SEEK_SET);
        if(r1 == -1)
        {
            LOGD("[!error!---] off_t do not exit");
            printf("[!error!---] off_t do not exit\n");
            continue;
        }
        else
        {
            char *buffer = malloc(len);
            ssize_t readlen = read(memory_fd, buffer, len);

            if(buffer[0] == 'd' && buffer[1] == 'e' && buffer[2] == 'x' && buffer[3] == '\n'  && buffer[4] == '0' && buffer[5] == '3')
            {
                LOGD("[*log*] find dex----- len : %d , info : %s" , readlen , mem_info);
                printf("[*log*] find dex----- len : %d , info : %s\n" , readlen , mem_info);
                DexHeader header;
                char real_lenstr[10]={0};
                memcpy(&header , buffer ,sizeof(DexHeader));
                sprintf(real_lenstr , "%x" , header.fileSize);
                //use the Dexhead struct to confirm the length
                long real_lennum = strtol(real_lenstr , NULL, 16);

                LOGD("[*log*] This dex's fileSize: %ld", real_lennum);
                printf("[*log*] This dex's fileSize: %ld\n", real_lennum);


                if(dump_memory_dex(buffer , len , each_filename)  == 1)
                {
                    LOGD("[*log*] dex dump into %s", each_filename);
                    printf("[*log*] dex dump into %s\n", each_filename);
                    free(buffer);
                    //this use continue or return? we can try again
                    continue;
                    // return 1;
                }
                else
                {
                    LOGD("[!error!] dex dump error");
                    printf("[!error!] dex dump error \n");
                }

            }
            free(buffer);
        }
    }
    fclose(maps_file);
    return ret;
}

/*
 * Dump buffer from Mem to file.
 * Dump a given memory location via a file descriptor, "memory_region"
 * and a given file_name for output.
 */

int dump_memory_dex(const char *buffer , int len , char each_filename[])
{
    int ret = -1;
    //printf("the file name is %s\n",each_filename);
    FILE *dump = fopen(each_filename, "wb");
    if(fwrite(buffer, len, 1, dump) != 1)
    {
        ret = -1;
    }
    else
    {
        ret = 1;
    }

    fclose(dump);
    return ret;
}