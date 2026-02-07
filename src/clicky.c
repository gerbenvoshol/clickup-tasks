#include "clicky.h"

// Callback function for libcurl to write response data into a memory buffer
size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        fprintf(stderr, "ERROR: not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// Read and parse .env file
int read_env_file(const char *env_path, Config *config) {
    FILE *fp = fopen(env_path, "r");
    if (!fp) {
        fprintf(stderr, "Error: .env file not found at '%s'\n", env_path);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Remove trailing newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') continue;
        
        // Parse KEY=VALUE
        char *equals = strchr(line, '=');
        if (!equals) continue;
        
        *equals = '\0';
        char *key = line;
        char *value = equals + 1;
        
        // Trim whitespace
        while (*key && isspace(*key)) key++;
        while (*value && isspace(*value)) value++;
        
        // Store values
        if (strcmp(key, "CLICKUP_TOKEN") == 0) {
            strncpy(config->clickup_token, value, sizeof(config->clickup_token) - 1);
        } else if (strcmp(key, "CLICKUP_LIST_ID") == 0) {
            strncpy(config->clickup_list_id, value, sizeof(config->clickup_list_id) - 1);
        } else if (strcmp(key, "SSH_USER") == 0) {
            strncpy(config->ssh_user, value, sizeof(config->ssh_user) - 1);
        } else if (strcmp(key, "SSH_PASS") == 0) {
            strncpy(config->ssh_pass, value, sizeof(config->ssh_pass) - 1);
        } else if (strcmp(key, "NODES") == 0) {
            // Parse space-separated nodes
            config->node_count = 0;
            char *token = strtok(value, " \t");
            while (token && config->node_count < MAX_NODES) {
                strncpy(config->nodes[config->node_count], token, 127);
                config->nodes[config->node_count][127] = '\0';
                config->node_count++;
                token = strtok(NULL, " \t");
            }
        }
    }

    fclose(fp);
    
    printf("Read .env variables from '%s'\n", env_path);
    return 0;
}

// Fetch tasks from ClickUp LIST API
int fetch_clickup_tasks(const char *token, const char *list_id, Task *tasks, int *task_count) {
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();

    // Build URL for list API (v2)
    char url[512];
    snprintf(url, sizeof(url), "https://api.clickup.com/api/v2/list/%s/task?archived=false", list_id);

    char auth_header[300];
    snprintf(auth_header, sizeof(auth_header), "Authorization: %s", token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "Clicky/1.4.4");

    res = curl_easy_perform(curl_handle);

    if(res != CURLE_OK) {
        fprintf(stderr, "ERROR: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl_handle);
        free(chunk.memory);
        curl_global_cleanup();
        return -1;
    }

    // Parse JSON response using mjson
    const char *json_str = chunk.memory;
    int json_len = (int)chunk.size;

    const char *tasks_ptr;
    int tasks_len;
    int tok_type = mjson_find(json_str, json_len, "$.tasks", &tasks_ptr, &tasks_len);

    if (tok_type != MJSON_TOK_ARRAY) {
        fprintf(stderr, "ERROR: 'tasks' is not an array in the JSON response.\n");
        if (chunk.size > 0 && chunk.size < 500) {
            fprintf(stderr, "Raw API response: \n%s\n", chunk.memory);
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl_handle);
        free(chunk.memory);
        curl_global_cleanup();
        return -1;
    }

    // Iterate through tasks
    *task_count = 0;
    int off = 0;
    int koff, klen, voff, vlen, vtype;
    
    while ((off = mjson_next(tasks_ptr, tasks_len, off, &koff, &klen, &voff, &vlen, &vtype)) != 0 && *task_count < MAX_TASKS) {
        const char *task_ptr = tasks_ptr + voff;
        int task_len = vlen;
        
        Task *task = &tasks[*task_count];
        task->comment_count = 0;
        
        // Extract name
        if (mjson_get_string(task_ptr, task_len, "$.name", task->name, sizeof(task->name)) <= 0) {
            strcpy(task->name, "N/A");
        }
        
        // Extract id
        if (mjson_get_string(task_ptr, task_len, "$.id", task->id, sizeof(task->id)) <= 0) {
            strcpy(task->id, "N/A");
        }
        
        // Extract due_date
        double due_date_dbl;
        if (mjson_get_number(task_ptr, task_len, "$.due_date", &due_date_dbl)) {
            task->due_date = (long)due_date_dbl;
        } else {
            task->due_date = 0;
        }
        
        // Extract status
        const char *status_obj_ptr;
        int status_obj_len;
        if (mjson_find(task_ptr, task_len, "$.status", &status_obj_ptr, &status_obj_len) == MJSON_TOK_OBJECT) {
            if (mjson_get_string(status_obj_ptr, status_obj_len, "$.status", task->status, sizeof(task->status)) <= 0) {
                strcpy(task->status, "N/A");
            }
        } else {
            strcpy(task->status, "N/A");
        }
        
        (*task_count)++;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_handle);
    free(chunk.memory);
    curl_global_cleanup();

    return 0;
}

// Fetch comments for a task
int fetch_task_comments(const char *token, const char *task_id, Task *task) {
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();

    char url[512];
    snprintf(url, sizeof(url), "https://api.clickup.com/api/v2/task/%s/comment", task_id);

    char auth_header[300];
    snprintf(auth_header, sizeof(auth_header), "Authorization: %s", token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "Clicky/1.4.4");

    res = curl_easy_perform(curl_handle);

    if(res == CURLE_OK) {
        const char *json_str = chunk.memory;
        int json_len = (int)chunk.size;

        const char *comments_ptr;
        int comments_len;
        int tok_type = mjson_find(json_str, json_len, "$.comments", &comments_ptr, &comments_len);

        if (tok_type == MJSON_TOK_ARRAY) {
            int off = 0;
            int koff, klen, voff, vlen, vtype;
            
            while ((off = mjson_next(comments_ptr, comments_len, off, &koff, &klen, &voff, &vlen, &vtype)) != 0 && task->comment_count < MAX_COMMENTS) {
                const char *comment_ptr = comments_ptr + voff;
                int comment_len = vlen;
                
                mjson_get_string(comment_ptr, comment_len, "$.comment_text", 
                                task->comments[task->comment_count], sizeof(task->comments[0]));
                task->comment_count++;
            }
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_handle);
    free(chunk.memory);
    curl_global_cleanup();

    return 0;
}

// Fetch processes from an HPC node via SSH
int fetch_node_processes(const char *node, const char *username, const char *password, ProcessInfo *processes, int *process_count) {
    ssh_session session;
    ssh_channel channel;
    int rc;
    char buffer[4096];
    int nbytes;

    session = ssh_new();
    if (session == NULL) {
        return -1;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, node);
    ssh_options_set(session, SSH_OPTIONS_USER, username);
    
    int timeout = 120;
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Failed to connect to %s: %s\n", node, ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    rc = ssh_userauth_password(session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Failed to authenticate to %s\n", node);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    rc = ssh_channel_request_exec(channel, "ps aux | grep -v grep");
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    // Read all output
    char full_output[MAX_LINE_LENGTH * 100] = "";
    int total_read = 0;
    
    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[nbytes] = '\0';
        if (total_read + nbytes < sizeof(full_output) - 1) {
            strcat(full_output, buffer);
            total_read += nbytes;
        }
    }

    // Parse ps output
    *process_count = 0;
    char *line = strtok(full_output, "\n");
    int skip_header = 1; // Skip first line (header)
    
    while (line && *process_count < MAX_PROCESSES) {
        if (skip_header) {
            skip_header = 0;
            line = strtok(NULL, "\n");
            continue;
        }
        
        ProcessInfo *proc = &processes[*process_count];
        strncpy(proc->node, node, sizeof(proc->node) - 1);
        
        // Parse ps output: USER PID %CPU %MEM ... COMMAND
        if (sscanf(line, "%63s %15s %15s %15s %*s %*s %*s %*s %*s %*s %511[^\n]",
                   proc->user, proc->pid, proc->cpu, proc->mem, proc->command) >= 5) {
            (*process_count)++;
        }
        
        line = strtok(NULL, "\n");
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    return 0;
}

// Escape HTML special characters
void escape_html(const char *input, char *output, size_t output_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < output_size - 6; i++) {
        switch (input[i]) {
            case '&':
                strcpy(&output[j], "&amp;");
                j += 5;
                break;
            case '<':
                strcpy(&output[j], "&lt;");
                j += 4;
                break;
            case '>':
                strcpy(&output[j], "&gt;");
                j += 4;
                break;
            case '"':
                strcpy(&output[j], "&quot;");
                j += 6;
                break;
            default:
                output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

// Generate HTML report
int generate_html_report(const char *output_file, Task *tasks, int task_count, ProcessInfo *processes, int process_count) {
    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot open output file %s\n", output_file);
        return -1;
    }

    // Write HTML header
    fprintf(fp, "<!DOCTYPE html>\n");
    fprintf(fp, "<html>\n<head>\n");
    fprintf(fp, "<title>Clicky - Task Status Report</title>\n");
    fprintf(fp, "<meta charset=\"UTF-8\">\n");
    fprintf(fp, "<style>\n");
    fprintf(fp, "body { font-family: Arial, sans-serif; margin: 20px; }\n");
    fprintf(fp, "h1 { color: #333; }\n");
    fprintf(fp, "table { border-collapse: collapse; width: 100%%; margin: 20px 0; }\n");
    fprintf(fp, "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
    fprintf(fp, "th { background-color: #4CAF50; color: white; }\n");
    fprintf(fp, "tr:nth-child(even) { background-color: #f2f2f2; }\n");
    fprintf(fp, ".status-open { color: #ff9800; font-weight: bold; }\n");
    fprintf(fp, ".status-in-progress { color: #2196F3; font-weight: bold; }\n");
    fprintf(fp, ".status-complete { color: #4CAF50; font-weight: bold; }\n");
    fprintf(fp, ".process { font-family: monospace; font-size: 0.9em; }\n");
    fprintf(fp, "</style>\n");
    fprintf(fp, "</head>\n<body>\n");
    fprintf(fp, "<h1>Clicky v%s - Task Status Report</h1>\n", VERSION);
    fprintf(fp, "<p>Generated: %s</p>\n", __DATE__ " " __TIME__);
    fprintf(fp, "<p>Total Tasks: %d | Total Processes: %d</p>\n", task_count, process_count);

    // Write tasks table
    fprintf(fp, "<h2>Tasks</h2>\n");
    fprintf(fp, "<table>\n");
    fprintf(fp, "<tr><th>Task Name</th><th>ID</th><th>Status</th><th>Due Date</th><th>Running Processes</th></tr>\n");

    for (int i = 0; i < task_count; i++) {
        Task *task = &tasks[i];
        
        char escaped_name[512];
        escape_html(task->name, escaped_name, sizeof(escaped_name));
        
        // Convert due date to readable format
        char due_date_str[64] = "N/A";
        if (task->due_date > 0) {
            time_t due = (time_t)(task->due_date / 1000); // Convert from milliseconds
            struct tm *tm_info = localtime(&due);
            strftime(due_date_str, sizeof(due_date_str), "%Y-%m-%d %H:%M", tm_info);
        }
        
        fprintf(fp, "<tr>\n");
        fprintf(fp, "  <td>%s</td>\n", escaped_name);
        fprintf(fp, "  <td>%s</td>\n", task->id);
        fprintf(fp, "  <td class=\"status-%s\">%s</td>\n", task->status, task->status);
        fprintf(fp, "  <td>%s</td>\n", due_date_str);
        
        // Find matching processes
        fprintf(fp, "  <td class=\"process\">");
        int found_process = 0;
        for (int j = 0; j < process_count; j++) {
            // Simple matching: check if task name appears in process command
            if (strstr(processes[j].command, task->name) != NULL) {
                if (found_process) fprintf(fp, "<br>");
                fprintf(fp, "[%s] %s", processes[j].node, processes[j].command);
                found_process = 1;
            }
        }
        if (!found_process) {
            fprintf(fp, "No matching processes");
        }
        fprintf(fp, "</td>\n");
        fprintf(fp, "</tr>\n");
    }

    fprintf(fp, "</table>\n");
    
    // Write processes table
    fprintf(fp, "<h2>All Processes</h2>\n");
    fprintf(fp, "<table>\n");
    fprintf(fp, "<tr><th>Node</th><th>User</th><th>PID</th><th>CPU%%</th><th>MEM%%</th><th>Command</th></tr>\n");
    
    for (int i = 0; i < process_count; i++) {
        ProcessInfo *proc = &processes[i];
        char escaped_cmd[1024];
        escape_html(proc->command, escaped_cmd, sizeof(escaped_cmd));
        
        fprintf(fp, "<tr>\n");
        fprintf(fp, "  <td>%s</td>\n", proc->node);
        fprintf(fp, "  <td>%s</td>\n", proc->user);
        fprintf(fp, "  <td>%s</td>\n", proc->pid);
        fprintf(fp, "  <td>%s</td>\n", proc->cpu);
        fprintf(fp, "  <td>%s</td>\n", proc->mem);
        fprintf(fp, "  <td class=\"process\">%s</td>\n", escaped_cmd);
        fprintf(fp, "</tr>\n");
    }
    
    fprintf(fp, "</table>\n");
    fprintf(fp, "</body>\n</html>\n");

    fclose(fp);
    return 0;
}

void print_usage(const char *program_name) {
    fprintf(stderr, "Clicky (Diagnostics Batch Runtime Monitor) v%s\n", VERSION);
    fprintf(stderr, "(C) Serge Wielhouwer - GenomeScan B.V. - Leiden 2025\n\n");
    fprintf(stderr, "Usage: %s [OPTIONS]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --html FILE   Output HTML report to FILE (default: task_status.html)\n");
    fprintf(stderr, "  -h, --help    Show this help message\n");
    fprintf(stderr, "\nEnvironment variables (from .env file):\n");
    fprintf(stderr, "  CLICKUP_TOKEN    Your ClickUp API token\n");
    fprintf(stderr, "  CLICKUP_LIST_ID  ClickUp list ID to monitor\n");
    fprintf(stderr, "  SSH_USER         SSH username for HPC nodes\n");
    fprintf(stderr, "  SSH_PASS         SSH password for HPC nodes\n");
    fprintf(stderr, "  NODES            Space-separated list of HPC nodes\n");
}

int main(int argc, char *argv[]) {
    Config config = {0};
    strcpy(config.html_out, "task_status.html");
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--html") == 0) {
            if (i + 1 < argc) {
                strncpy(config.html_out, argv[++i], sizeof(config.html_out) - 1);
            } else {
                fprintf(stderr, "ERROR: --html requires a file path\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown parameter: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    printf("HTML report will be written to: %s\n", config.html_out);
    
    // Determine script folder and pipeline root
    char script_folder[512];
    char pipeline_root[512];
    
    // Get the directory of the executable
    ssize_t len = readlink("/proc/self/exe", script_folder, sizeof(script_folder) - 1);
    if (len != -1) {
        script_folder[len] = '\0';
        char *last_slash = strrchr(script_folder, '/');
        if (last_slash) *last_slash = '\0';
    } else {
        getcwd(script_folder, sizeof(script_folder));
    }
    
    // Try multiple locations for .env file
    char env_path[1024];
    int env_found = 0;
    
    // Try current directory first
    snprintf(env_path, sizeof(env_path), ".env");
    if (access(env_path, R_OK) == 0) {
        env_found = 1;
    } else {
        // Try script folder
        snprintf(env_path, sizeof(env_path), "%s/.env", script_folder);
        if (access(env_path, R_OK) == 0) {
            env_found = 1;
        } else {
            // Try parent of script folder (pipeline root)
            strncpy(pipeline_root, script_folder, sizeof(pipeline_root));
            char *last_slash = strrchr(pipeline_root, '/');
            if (last_slash) *last_slash = '\0';
            snprintf(env_path, sizeof(env_path), "%s/.env", pipeline_root);
            if (access(env_path, R_OK) == 0) {
                env_found = 1;
            }
        }
    }
    
    if (!env_found) {
        fprintf(stderr, "Error: .env file not found in current directory, script folder, or pipeline root\n");
        return 1;
    }
    
    // Read .env file
    if (read_env_file(env_path, &config) < 0) {
        return 1;
    }
    
    // Validate configuration
    if (strlen(config.clickup_token) == 0 || strlen(config.clickup_list_id) == 0) {
        fprintf(stderr, "ERROR: CLICKUP_TOKEN and CLICKUP_LIST_ID must be set in .env file\n");
        return 1;
    }
    
    // Fetch ClickUp tasks
    printf("Fetching tasks from ClickUp...\n");
    Task *tasks = calloc(MAX_TASKS, sizeof(Task));
    int task_count = 0;
    
    if (fetch_clickup_tasks(config.clickup_token, config.clickup_list_id, tasks, &task_count) < 0) {
        fprintf(stderr, "ERROR: Failed to fetch ClickUp tasks\n");
        free(tasks);
        return 1;
    }
    
    printf("Fetched %d tasks\n", task_count);
    
    // Fetch comments for each task
    printf("Fetching task comments...\n");
    for (int i = 0; i < task_count; i++) {
        fetch_task_comments(config.clickup_token, tasks[i].id, &tasks[i]);
    }
    
    // Fetch processes from HPC nodes
    printf("Fetching processes from HPC nodes...\n");
    ProcessInfo *processes = calloc(MAX_PROCESSES, sizeof(ProcessInfo));
    int process_count = 0;
    
    for (int i = 0; i < config.node_count; i++) {
        printf("Fetching processes from %s... ", config.nodes[i]);
        fflush(stdout);
        
        ProcessInfo *node_processes = calloc(MAX_PROCESSES, sizeof(ProcessInfo));
        int node_process_count = 0;
        
        if (fetch_node_processes(config.nodes[i], config.ssh_user, config.ssh_pass, 
                                 node_processes, &node_process_count) == 0) {
            printf("Success (%d processes)\n", node_process_count);
            
            // Append to main process list
            for (int j = 0; j < node_process_count && process_count < MAX_PROCESSES; j++) {
                processes[process_count++] = node_processes[j];
            }
        } else {
            printf("Failed\n");
        }
        
        free(node_processes);
    }
    
    printf("Total processes fetched: %d\n", process_count);
    
    // Generate HTML report
    printf("Generating HTML report...\n");
    if (generate_html_report(config.html_out, tasks, task_count, processes, process_count) < 0) {
        free(tasks);
        free(processes);
        return 1;
    }
    
    printf("Report written to %s\n", config.html_out);
    
    free(tasks);
    free(processes);
    
    return 0;
}
