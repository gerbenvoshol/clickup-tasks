#ifndef CLICKY_H
#define CLICKY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <curl/curl.h>
#include <libssh/libssh.h>
#include "mjson.h"

#define VERSION "1.4.4"
#define MAX_NODES 100
#define MAX_TASKS 1000
#define MAX_COMMENTS 100
#define MAX_PROCESSES 10000
#define MAX_LINE_LENGTH 4096

// Memory structure for libcurl responses
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Task structure
typedef struct {
    char name[256];
    char id[64];
    long due_date;
    char status[64];
    char comments[MAX_COMMENTS][1024];
    int comment_count;
} Task;

// Process info structure
typedef struct {
    char node[128];
    char user[64];
    char pid[16];
    char cpu[16];
    char mem[16];
    char command[512];
} ProcessInfo;

// Configuration structure
typedef struct {
    char clickup_token[256];
    char clickup_list_id[64];
    char ssh_user[64];
    char ssh_pass[256];
    char nodes[MAX_NODES][128];
    int node_count;
    char html_out[512];
} Config;

// Function prototypes
size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
int read_env_file(const char *env_path, Config *config);
int fetch_clickup_tasks(const char *token, const char *list_id, Task *tasks, int *task_count);
int fetch_task_comments(const char *token, const char *task_id, Task *task);
int fetch_node_processes(const char *node, const char *username, const char *password, ProcessInfo *processes, int *process_count);
int generate_html_report(const char *output_file, Task *tasks, int task_count, ProcessInfo *processes, int process_count);
void escape_html(const char *input, char *output, size_t output_size);
void print_usage(const char *program_name);

#endif /* CLICKY_H */
