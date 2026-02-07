#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <libssh/libssh.h>
#include <math.h>
#include "mjson.h"

#define ID_WIDTH 10
#define NAME_WIDTH 40
#define STATUS_WIDTH 15
#define ASSIGNEES_WIDTH 80

struct MemoryStruct {
  char *memory;
  size_t size;
};

size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
void print_table_separator();
void print_table_header();
void print_table_row(const char *id, const char *name, const char *status, const char *assignees);

// SSH job monitoring functions
int run_ssh_command(ssh_session session, const char *command);
int monitor_jobs_on_node(const char *host, int port, const char *username, const char *password, const char *job_filter);
void print_usage(const char *program_name);

#endif /* MAIN_H */
