#include "main.h"

// Callback function for libcurl to write response data into a memory buffer
size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void print_table_separator() {

    printf("+");

    for (int i = 0; i < ID_WIDTH + 2; i++) printf("-");

    printf("+");

    for (int i = 0; i < NAME_WIDTH + 2; i++) printf("-");

    printf("+");

    for (int i = 0; i < STATUS_WIDTH + 2; i++) printf("-");

    printf("+");

    for (int i = 0; i < ASSIGNEES_WIDTH + 2; i++) printf("-");

    printf("+\n");

}



void print_table_header() {

    print_table_separator();

    printf("| %-*s | %-*s | %-*s | %-*s |\n", ID_WIDTH, "ID", NAME_WIDTH, "Name", STATUS_WIDTH, "Status", ASSIGNEES_WIDTH, "Assignees");

    print_table_separator();

}



void print_table_row(const char *id, const char *name, const char *status, const char *assignees) {

    char truncated_name[NAME_WIDTH + 1];



    strncpy(truncated_name, name, NAME_WIDTH);

    truncated_name[NAME_WIDTH] = '\0';

    if (strlen(name) > NAME_WIDTH) {

        strcpy(truncated_name + NAME_WIDTH - 3, "...");

    }



    printf("| %-*s | %-*s | %-*s | %-*s |\n", ID_WIDTH, id, NAME_WIDTH, truncated_name, STATUS_WIDTH, status, ASSIGNEES_WIDTH, assignees);

}

// SSH command execution function
int run_ssh_command(ssh_session session, const char *command) {
    ssh_channel channel;
    int rc;
    char buffer[2048];
    int nbytes;

    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0) {
        if (fwrite(buffer, 1, (size_t)nbytes, stdout) != (size_t)nbytes) {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

// Monitor jobs on a specific node
int monitor_jobs_on_node(const char *host, int port, const char *username, const char *password, const char *job_filter) {
    ssh_session session;
    int rc;

    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        return -1;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, username);

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to %s: %s\n", host, ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    rc = ssh_userauth_password(session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    printf("\n=== Jobs on %s ===\n", host);
    
    // Build ps command with optional filter
    // Note: We use a simple whitelist validation for the filter to prevent command injection
    char command[512];
    if (job_filter && strlen(job_filter) > 0) {
        // Validate filter contains only safe characters (alphanumeric, dash, underscore, dot, slash)
        int is_safe = 1;
        for (const char *p = job_filter; *p; p++) {
            if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.' && *p != '/') {
                is_safe = 0;
                break;
            }
        }
        
        if (is_safe) {
            snprintf(command, sizeof(command), "ps aux | grep '%s' | grep -v grep", job_filter);
        } else {
            fprintf(stderr, "Warning: job filter contains unsafe characters, using unfiltered ps\n");
            snprintf(command, sizeof(command), "ps aux");
        }
    } else {
        snprintf(command, sizeof(command), "ps aux");
    }
    
    rc = run_ssh_command(session, command);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error running command: %s\n", ssh_get_error(session));
    }

    ssh_disconnect(session);
    ssh_free(session);

    return (rc == SSH_OK) ? 0 : -1;
}

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [OPTIONS]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -m            Monitor jobs mode - check running jobs on HPC nodes\n");
    fprintf(stderr, "  -n NODES      Comma-separated list of nodes (e.g., 'node1:22,node2:22')\n");
    fprintf(stderr, "  -u USERNAME   SSH username for job monitoring\n");
    fprintf(stderr, "  -p PASSWORD   SSH password for job monitoring (WARNING: visible in process list)\n");
    fprintf(stderr, "  -f FILTER     Filter jobs by name/pattern (alphanumeric, -, _, ., / only)\n");
    fprintf(stderr, "  -h            Show this help message\n");
    fprintf(stderr, "\nEnvironment variables (for ClickUp tasks):\n");
    fprintf(stderr, "  CLICKUP_TOKEN   Your ClickUp API token\n");
    fprintf(stderr, "  CLICKUP_USERID  Your ClickUp user ID\n");
    fprintf(stderr, "  CLICKUP_TEAMID  Your ClickUp team ID\n");
    fprintf(stderr, "\nSecurity note:\n");
    fprintf(stderr, "  Command-line passwords are visible in process listings. For production\n");
    fprintf(stderr, "  use, consider using SSH keys or prompting for passwords interactively.\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s                           # List ClickUp tasks\n", program_name);
    fprintf(stderr, "  %s -m -n 'node1:22,node2:22' -u user -p pass  # Monitor all jobs\n", program_name);
    fprintf(stderr, "  %s -m -n 'node1:22' -u user -p pass -f 'python'  # Monitor Python jobs\n", program_name);
}



int main(int argc, char *argv[]) {
    // Parse command line options
    int opt;
    int monitor_mode = 0;
    char *nodes = NULL;
    char *ssh_username = NULL;
    char *ssh_password = NULL;
    char *job_filter = NULL;

    while ((opt = getopt(argc, argv, "mn:u:p:f:h")) != -1) {
        switch (opt) {
            case 'm':
                monitor_mode = 1;
                break;
            case 'n':
                nodes = optarg;
                break;
            case 'u':
                ssh_username = optarg;
                break;
            case 'p':
                ssh_password = optarg;
                break;
            case 'f':
                job_filter = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // If in monitor mode, check jobs on nodes
    if (monitor_mode) {
        if (!nodes || !ssh_username || !ssh_password) {
            fprintf(stderr, "Error: Monitor mode requires -n (nodes), -u (username), and -p (password)\n\n");
            print_usage(argv[0]);
            return 1;
        }

        // Parse nodes and monitor each one
        char *nodes_copy = strdup(nodes);
        char *token = strtok(nodes_copy, ",");
        
        while (token != NULL) {
            // Parse host:port
            char *colon = strchr(token, ':');
            if (colon) {
                *colon = '\0';
                char *host = token;
                int port = atoi(colon + 1);
                
                if (port > 0 && port < 65536) {
                    monitor_jobs_on_node(host, port, ssh_username, ssh_password, job_filter);
                } else {
                    fprintf(stderr, "Invalid port for node %s\n", host);
                }
            } else {
                // Default to port 22
                monitor_jobs_on_node(token, 22, ssh_username, ssh_password, job_filter);
            }
            
            token = strtok(NULL, ",");
        }
        
        free(nodes_copy);
        return 0;
    }

    // Default mode: Fetch ClickUp tasks
    // 1. Get config from environment variables

    const char *token = getenv("CLICKUP_TOKEN");

    const char *user_id = getenv("CLICKUP_USERID");

    const char *team_id = getenv("CLICKUP_TEAMID");



    if (!token || !user_id || !team_id) {

        fprintf(stderr, "Error: Please set CLICKUP_TOKEN, CLICKUP_USERID, and CLICKUP_TEAMID environment variables.\n");

        return 1;

    }



    CURL *curl_handle;

    CURLcode res;



    struct MemoryStruct chunk;

    chunk.memory = malloc(1);

    chunk.size = 0;



    // 2. Prepare the API request

    curl_global_init(CURL_GLOBAL_ALL);

    curl_handle = curl_easy_init();



    char url[512]; // Increased buffer size for URL

    snprintf(url, sizeof(url), "https://api.clickup.com/api/v3/team/%s/task?assignees[]=%s&include_closed=false", team_id, user_id);



    char auth_header[256];

    snprintf(auth_header, sizeof(auth_header), "Authorization: %s", token);



    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, auth_header);



    curl_easy_setopt(curl_handle, CURLOPT_URL, url);

    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");



    // 3. Perform the request

    res = curl_easy_perform(curl_handle);



    if(res != CURLE_OK) {

        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    } else {

        // 4. Parse JSON response using mjson
        const char *json_str = chunk.memory;
        int json_len = (int)chunk.size;

        // Check if JSON is valid
        const char *tasks_ptr;
        int tasks_len;
        int tok_type = mjson_find(json_str, json_len, "$.tasks", &tasks_ptr, &tasks_len);

        if (tok_type != MJSON_TOK_ARRAY) {
            fprintf(stderr, "error: 'tasks' is not an array in the JSON response.\n");
            if (chunk.size > 0) {
                fprintf(stderr, "Raw API response (first 500 chars): \n%.*s\n", (int)fmin(chunk.size, 500), chunk.memory);
            }
            free(chunk.memory);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl_handle);
            curl_global_cleanup();
            return 1;
        }

        // Count tasks by iterating through the array
        int task_count = 0;
        int off = 0;
        int koff, klen, voff, vlen, vtype;
        while ((off = mjson_next(tasks_ptr, tasks_len, off, &koff, &klen, &voff, &vlen, &vtype)) != 0) {
            task_count++;
        }

        if (task_count == 0) {
            printf("No tasks found.\n");
        } else {
            print_table_header();

            // Iterate through tasks again and print them
            off = 0;
            while ((off = mjson_next(tasks_ptr, tasks_len, off, &koff, &klen, &voff, &vlen, &vtype)) != 0) {
                const char *task_ptr = tasks_ptr + voff;
                int task_len = vlen;

                // Extract custom_id
                char custom_id[ID_WIDTH + 1] = "N/A";
                mjson_get_string(task_ptr, task_len, "$.custom_id", custom_id, sizeof(custom_id));

                // Extract name
                char name[NAME_WIDTH + 1] = "N/A";
                mjson_get_string(task_ptr, task_len, "$.name", name, sizeof(name));

                // Extract status
                char status_str[STATUS_WIDTH + 1] = "N/A";
                const char *status_obj_ptr;
                int status_obj_len;
                if (mjson_find(task_ptr, task_len, "$.status", &status_obj_ptr, &status_obj_len) == MJSON_TOK_OBJECT) {
                    mjson_get_string(status_obj_ptr, status_obj_len, "$.status", status_str, sizeof(status_str));
                }

                // Extract assignees
                char assignees_str_buf[ASSIGNEES_WIDTH + 1];
                assignees_str_buf[0] = '\0';
                size_t current_len = 0;

                const char *assignees_arr_ptr;
                int assignees_arr_len;
                if (mjson_find(task_ptr, task_len, "$.assignees", &assignees_arr_ptr, &assignees_arr_len) == MJSON_TOK_ARRAY) {
                    int assignee_off = 0;
                    int assignee_koff, assignee_klen, assignee_voff, assignee_vlen, assignee_vtype;
                    
                    while ((assignee_off = mjson_next(assignees_arr_ptr, assignees_arr_len, assignee_off, 
                                                      &assignee_koff, &assignee_klen, &assignee_voff, &assignee_vlen, &assignee_vtype)) != 0) {
                        const char *assignee_ptr = assignees_arr_ptr + assignee_voff;
                        int assignee_len = assignee_vlen;
                        
                        char username[100];
                        if (mjson_get_string(assignee_ptr, assignee_len, "$.username", username, sizeof(username)) > 0) {
                            if (current_len > 0) {
                                size_t remaining_space = ASSIGNEES_WIDTH - current_len;
                                if (remaining_space > 0) {
                                    strncat(assignees_str_buf, ", ", remaining_space);
                                    current_len += fmin(remaining_space, 2);
                                }
                            }
                            
                            size_t remaining_space = ASSIGNEES_WIDTH - current_len;
                            if (remaining_space > 0) {
                                strncat(assignees_str_buf, username, remaining_space);
                                current_len += fmin(remaining_space, strlen(username));
                            }
                        }
                        
                        if (current_len >= ASSIGNEES_WIDTH) {
                            break;
                        }
                    }
                }
                
                if (assignees_str_buf[0] == '\0') {
                    strncpy(assignees_str_buf, "N/A", ASSIGNEES_WIDTH);
                    assignees_str_buf[ASSIGNEES_WIDTH] = '\0';
                } else {
                    if (current_len < ASSIGNEES_WIDTH) {
                        assignees_str_buf[current_len] = ' ';
                        assignees_str_buf[current_len + 1] = '\0';
                    }
                }

                print_table_row(custom_id, name, status_str, assignees_str_buf);
            }

            print_table_separator();
        }
    }



    // 6. Cleanup

    curl_slist_free_all(headers);

    curl_easy_cleanup(curl_handle);

    free(chunk.memory);

    curl_global_cleanup();



    return 0;

}




