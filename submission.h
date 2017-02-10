#ifndef _SUBMISSION_H_
#define _SUBMISSION_H_

#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SUBMISSION_POSSIBLE_SERVICES "anubis, dummy"

struct result_buffer {
    char* buffer;
    int size;
    char* parsed_url;
};

// The public API

void submission_set_service(char* service);
void submission_submit(char* filename);
struct result_buffer* submission_current_result();
char* submission_current_url();


// anubis
CURL* curl_anubis;
struct result_buffer* rb;
void submit_to_anubis(char* filename);
size_t submission_get_response_anubis(void* buffer, size_t size, size_t nmemb, void* userp); 
void parse_url_anubis(struct result_buffer*);

// dummy
void submit_to_dummy(char* filename);

// internal functions
void submission_init();
void submission_destroy();
extern char* submission_service;
extern int   submission_do_submission;


#endif
