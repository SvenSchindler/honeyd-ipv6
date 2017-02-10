#include <sys/types.h>
#include <sys/stat.h>       // for mkdir
#include <errno.h>          // for errno, EEXIST
#include <stdio.h>
#include <string.h>         // for memcpy
#include <openssl/md5.h>
#include <stdlib.h>

#include "shellcode.h"
#include "database.h"       // for DB_PROTO_{TCP,UDP}
#include <emu/emu.h>
#include <emu/emu_getpc.h>

struct emu* e;

// uses libemu's getpc_check to see if a buffer contains a possible getpc check.
// does not emulate or profile the shellcode
// returns -1 if no getpc check was found or the number of the first byte that was identified as being
// a possible getpc
// Copied (in parts) from libemu's sctestmain.c
int shellcode_test(char *buf, int size)
{
#ifdef SHELLCODE_DEBUG
	shellcode_hex_dump("inside shellcode_test", buf, size);
#endif

	// iterate over every byte in the buffer and check it
	int offset;
	for (offset = 0; offset < size; offset++)
	{
		if (emu_getpc_check(e, (uint8_t *) buf, size, offset) != 0)
			return offset;
	}

	// no getpc code found
	return -1;
}

// from http://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
// prints a hexdump of a memory region at addr. Prints the description from desc. 
void shellcode_hex_dump(char *desc, void *addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = addr;

	// Output description if given.
	if (desc != NULL )
		printf("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++)
	{
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0)
		{
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0)
	{
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

// writes at max len bytes from buffer buf to the shellcode buffer inside the connection con.
// will make sure that the max length of shellcode_buf (SHELLCODE_BUF_MAXSIZE) is not exceeded.
//
// works for both contypes (UDP, and TCP) use DB_PROTO_TCP and DB_PROTO_UDP from database.h for specifiying the type. 
void shellcode_write_to_buffer(void* arg, int contype, char* buf, u_int len)
{

	if (contype == DB_PROTO_TCP)
	{
		struct tcp_con* con = arg;

#ifdef SHELLCODE_DEBUG
		shellcode_hex_dump("Input", buf, len);
#endif

		if ((con->shellcode_size + len) > SHELLCODE_BUF_MAXSIZE)
		{

			printf(
					"Shellcode warning: Couldn't write everything to the buffer because it was too large. Truncating input.\n");

			if ((memcpy(con->shellcode_buf + con->shellcode_size, buf,
					SHELLCODE_BUF_MAXSIZE - con->shellcode_size)) == NULL )
			{
				printf(
						"Shellcode error: Tried to memcpy but that didn't work!\n");
				return;
			}

			con->shellcode_size = SHELLCODE_BUF_MAXSIZE;
		}
		else
		{
			if ((memcpy(con->shellcode_buf + con->shellcode_size, buf, len))
					== NULL )
			{
				printf(
						"Shellcode error: Tried to memcpy but that didn't work!\n");
				return;
			}

			con->shellcode_size += len;
		}

#ifdef SHELLCODE_DEBUG
		shellcode_hex_dump("shellcode_buf", con->shellcode_buf, con->shellcode_size);
#endif

	}
	else if (contype == DB_PROTO_UDP)
	{
		struct udp_con* con = arg;

#ifdef SHELLCODE_DEBUG
		shellcode_hex_dump("Input", buf, len);
#endif

		if ((con->shellcode_size + len) > SHELLCODE_BUF_MAXSIZE)
		{

			printf(
					"Shellcode warning: Couldn't write everything to the buffer because it was too large. Truncating input.\n");

			if ((memcpy(con->shellcode_buf + con->shellcode_size, buf,
					SHELLCODE_BUF_MAXSIZE - con->shellcode_size)) == NULL )
			{
				printf(
						"Shellcode error: Tried to memcpy but that didn't work!\n");
				return;
			}

			con->shellcode_size = SHELLCODE_BUF_MAXSIZE;
		}
		else
		{
			if ((memcpy(con->shellcode_buf + con->shellcode_size, buf, len))
					== NULL )
			{
				printf(
						"Shellcode error: Tried to memcpy but that didn't work!\n");
				return;
			}

			con->shellcode_size += len;
		}

#ifdef SHELLCODE_DEBUG
		shellcode_hex_dump("shellcode_buf", con->shellcode_buf, con->shellcode_size);
#endif

	}
	else
	{
		printf(
				"Shellcode warning: tried to call shellcode_write_to_buffer with wrong argument contype.\n\
                Make sure it's either DB_PROTO_TCP or DB_PROTO_UDP.\n");
		return;
	}
}

// thank you http://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
char *str2md5(const char *str, int length)
{
	int n;
	MD5_CTX c;
	unsigned char digest[16];
	char *out = (char*) malloc(33);

	MD5_Init(&c);

	while (length > 0)
	{
		if (length > 512)
		{
			MD5_Update(&c, str, 512);
		}
		else
		{
			MD5_Update(&c, str, length);
		}
		length -= 512;
		str += 512;
	}

	MD5_Final(digest, &c);

	for (n = 0; n < 16; ++n)
	{
		snprintf(&(out[n * 2]), 16 * 2, "%02x", (unsigned int) digest[n]);
	}

	return out;
}

// converts a raw shellcode to a windows executable pe-file using
// metasploit's MSFENCODE script.
//
// will get the md5 hash of the shellcode and create a subdirectory named after the hash
// will place the exe in that directory.
// returns the md5 hash on success or NULL on failure
//
// Note: if the subdirectory is already present MSFENCODE will not be started again
char* shellcode_convert(char* buf, int size)
{

	// get the md5 hash of the buffer - this will be the subdir-name
	char* md5 = str2md5(buf, size);
	if (md5 == NULL )
	{
		printf("shellcode error: couldn't get md5 hash.\n");
		return NULL ;
	}

	// make new directory
	char* filepath;
	if (asprintf(&filepath, "%s/%s", database_shellcodedir, md5) == NULL )
	{
		printf("shellcode error: couldn't asprintf into the filepath string\n");
		free(md5);
		free(filepath);
		return NULL ;
	}

	/*
	 * strange Bitmasks.. *sigh*
	 * S_IFDIR - it's a directory!
	 * S_IRUSR, S_IWUSR, S_IXUSR - User has read, write or execute permissions, respectively
	 * S_IRWXU, S_IRWXG, S_IRWXO - Read, Write and Execute permissions for user, group and others, respecitvely
	 */
	if (mkdir(filepath,
			S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0)
	{

		// directory already exists - we assume the shellcode is already present in exe
		// simply return the md5
		if (errno == EEXIST)
		{
			return md5;
		}
		else
		{
			perror("error creating directory");
			free(md5);
			free(filepath);
			return NULL ;
		}
	}

	// create another process that calls msfencode
	FILE* msfe_pipe;
	char* command;

	// prepare the command the child process should run
	if (asprintf(&command,
			"msfencode -a x86 -e generic/none -t exe -o %s/shellcode.exe",
			filepath, md5) == NULL )
	{
		printf("shellcode error: couldn't asprintf into the command string\n");
		free(md5);
		free(command);
		return NULL ;
	}

	// spwan the child
	if ((msfe_pipe = popen(command, "w")) == NULL )
	{
		printf("shellcode error: couldn't spawn pipe for msfencode\n");
		free(md5);
		free(command);

		return NULL ;
	}

	// write to child
	fputs(buf, msfe_pipe);
	fputc('\n', msfe_pipe);

	pclose(msfe_pipe);
	free(command);

	return md5;
}

// initializes the emulator 
void shellcode_init()
{

	// activate the emulator
	e = emu_new();
}

void shellcode_destroy()
{
	emu_free(e);
}

