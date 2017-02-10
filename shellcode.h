#include <sys/types.h>
#include <database.h>
#include <sys/queue.h>

#ifndef _SHELLCODE_H_
#define _SHELLCODE_H_

#define SHELLCODE_BUF_MAXSIZE 8192
//#define SHELLCODE_BUF_CHUNKSIZE 128

//#define SHELLCODE_DEBUG


struct shellcode {
    char* buf;
    int size;
    int database_id;
    int state;
    char* filename;
    char* report_url;
    TAILQ_ENTRY(shellcode) entries;
};


extern struct emu* e;

int shellcode_test(char*, int);
char* str2md5(const char*, int);
char* shellcode_convert(char*, int);
void shellcode_hex_dump(char*, void*, int);
void shellcode_write_to_buffer(void*, int, char*, u_int);
void shellcode_init();
void shellcode_destroy();

#endif


