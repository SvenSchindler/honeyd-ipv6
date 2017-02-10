#include "submission.h"

char* submission_service = NULL;
int submission_do_submission = 0;

void submission_submit(char* filename)
{

	if (strncmp(submission_service, "anubis", 6) == 0)
	{
		submit_to_anubis(filename);
	}
	else if (strncmp(submission_service, "dummy", 5) == 0)
	{
		submit_to_dummy(filename);
	}

}

void submit_to_dummy(char* filename)
{

	rb->parsed_url = "http://www.example.com/";
	rb->buffer = "loremipsum";
	rb->size = 10;

	printf("Submission: Submitted %s to the Dummy Service.\n", filename);
}

// submit a file specified by filename to the anubis webservice
// using HTTP POST. POSTs transfer data in the header using a
// key-value mapping
void submit_to_anubis(char* filename)
{

	// reset the form data
	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastitem = NULL;

	// adds the key "executable" and uses the filename as a value
	curl_formadd(&formpost, &lastitem, CURLFORM_COPYNAME, "executable",
			CURLFORM_FILE, filename, CURLFORM_END);

	// use the form we just prepared
	curl_easy_setopt(curl_anubis, CURLOPT_HTTPPOST, formpost);

	// reset the receive_buffer
	free(rb->buffer);
	rb->buffer = malloc(1);
	rb->size = 0;

	// perform the request
	int result = curl_easy_perform(curl_anubis);
	if (result != CURLE_OK)
		printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(result));

	curl_formfree(formpost);
	parse_url_anubis(rb);
}

size_t submission_get_response_anubis(void* buffer, size_t size, size_t nmemb,
		void* userp)
{

	struct result_buffer* rb = (struct result_buffer*) userp;

	size_t realsize = size * nmemb;

	// grow the buffer as needed
	rb->buffer = realloc(rb->buffer, rb->size + realsize);
	if (rb->buffer == NULL )
	{
		printf(
				"submission error: couldn't allocate enough memory for the server's response\n");
		exit(EXIT_FAILURE);
	}

	// copy the response from teh server to the receive buffer,
	// offset by the size that's currently in it
	if (memcpy(rb->buffer + rb->size, buffer, realsize) == NULL )
	{
		printf(
				"submission error: couldn't copy the server's response into internal memory.\n");
		exit(EXIT_FAILURE);
	}

	rb->size += realsize;

	return realsize;
}

void parse_url_anubis(struct result_buffer* buffer)
{

	char* begin_match = "<meta http-equiv=\"refresh\" content=\"10; URL=";
	char* end_match = "&call=first\"/>";

	// set beginning to position of first occurance of begin_match
	char* beginning = strstr(buffer->buffer, begin_match);

	// set end to position of first occurance of end_match
	char* end = strstr(buffer->buffer, end_match);

	// pointer arithmetic: this will work out how long the string
	// between the two matches is.
	// you have to exclude the length of the first match
	int position_beginning = beginning - buffer->buffer;
	int position_end = end - buffer->buffer;
	int url_length = position_end - position_beginning - strlen(begin_match);

	// now allocate enough space inside the result_buffer
	buffer->parsed_url = calloc(url_length + 1, sizeof(char));
	if (buffer->parsed_url == NULL )
	{
		printf(
				"submission error: couldn't allocate enough memory for the parsed url.\n");
		exit(EXIT_FAILURE);
	}
	char* result = strncpy(buffer->parsed_url, beginning + strlen(begin_match),
			url_length);
	if (result == NULL )
	{
		printf(
				"submission error: copying the parsed url into internal memory failed.\n");
		exit(EXIT_FAILURE);
	}
}

struct result_buffer* submission_current_result()
{

	return rb;
}

char* submission_current_url()
{
	return rb->parsed_url;
}

void submission_init()
{
	// setup the result_buffer
	rb = calloc(1, sizeof(struct result_buffer));
	rb->buffer = calloc(1, 1);
	rb->size = 0;
	rb->parsed_url = calloc(1, 1);

	// init Anubis
	if (submission_service != NULL
			&& strncmp(submission_service, "anubis", 6) == 0)
	{
		// setup curl
		curl_global_init(CURL_GLOBAL_ALL);
		curl_anubis = curl_easy_init();

		if (!curl_anubis)
		{
			printf("submission error: couldn't init curl.\n");
			exit(EXIT_FAILURE);
		}

		// set the url
		curl_easy_setopt(curl_anubis, CURLOPT_URL,
				"http://anubis.iseclab.org/?action=analyze");
		curl_easy_setopt(curl_anubis, CURLOPT_WRITEFUNCTION,
				submission_get_response_anubis);
		curl_easy_setopt(curl_anubis, CURLOPT_WRITEDATA, (void* ) rb);
	}

}

void submission_destroy()
{
	curl_easy_cleanup(curl_anubis);
	free(rb->buffer);
	free(rb);
}

void submission_set_service(char* service)
{
	submission_do_submission = 0;
	if (service == NULL )
	{
		fprintf(stderr,
				"Error setting the submission service. Please use one of the following: %s. Submission is disabled\n",
				SUBMISSION_POSSIBLE_SERVICES);
		return;
	}

	if (strncmp(service, "anubis", 6) == 0)
	{
		submission_service = service;
		submission_do_submission = 1;
	}
	else if (strncmp(service, "dummy", 5) == 0)
	{
		submission_service = service;
		submission_do_submission = 1;
	}

	if (submission_do_submission == 1)
		printf("Submission info: Will submit Shellcodes to %s.\n",
				submission_service);
}
