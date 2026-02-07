# C ClickUp Tasks Tools

This repository contains two C-based tools for working with ClickUp and HPC monitoring:

1. **clickup_tasks**: Simple command-line tool to fetch and display ClickUp tasks
2. **clicky**: Diagnostics Batch Runtime Monitor - correlates ClickUp tasks with running HPC jobs

## Features

### clickup_tasks
- Fetch and display ClickUp tasks in a formatted table
- Monitor running jobs on HPC nodes using SSH
- Filter jobs by name/pattern using ps command
- Uses lightweight mjson library for JSON parsing

### clicky (Diagnostics Batch Runtime Monitor)
- **Version**: 1.4.4
- Fetches tasks from a specific ClickUp list
- Monitors running processes on multiple HPC nodes via SSH
- Correlates tasks with running jobs
- Generates HTML reports showing task status and process information
- Reads configuration from .env file

## Prerequisites

Before compiling and running this project, you need to have the following libraries installed:

*   **libcurl**: For making HTTP requests to the ClickUp API.
*   **libssh**: For SSH connectivity to HPC nodes for job monitoring.

Note: The mjson library for JSON parsing is included in the source code and does not require separate installation.

You can typically install these on a Debian-based system (like Ubuntu) using:

```bash
sudo apt-get update
sudo apt-get install libcurl4-openssl-dev libssh-dev
```

## Compilation

To compile both tools, simply run the `make` command in the project's root directory:

```bash
make
```

This will generate two executable files:
- `clickup_tasks` - The simple task lister
- `clicky` - The diagnostics batch runtime monitor

## Usage

### clickup_tasks - Simple Task Lister

#### List ClickUp Tasks

To run the program in default mode (list ClickUp tasks), set environment variables:

```bash
export CLICKUP_TOKEN="your_api_token"
export CLICKUP_USERID="your_user_id"
export CLICKUP_TEAMID="your_team_id"

./clickup_tasks
```

#### Monitor Jobs on HPC Nodes

```bash
./clickup_tasks -m -n "node1:22,node2:22" -u username -p password
```

### clicky - Diagnostics Batch Runtime Monitor

#### Configuration

Clicky reads its configuration from a `.env` file:

```bash
cp .env.example .env
# Edit .env with your settings
```

The `.env` file should contain:

```bash
CLICKUP_TOKEN=your_clickup_api_token
CLICKUP_LIST_ID=your_list_id
SSH_USER=your_ssh_username
SSH_PASS=your_ssh_password
NODES=node1 node2 node3
```

#### Running clicky

```bash
./clicky                          # Generate task_status.html
./clicky --html /path/to/report.html  # Custom output file
```

#### How it Works

1. Reads configuration from `.env` file
2. Fetches tasks from ClickUp list (API v2)
3. Fetches comments for each task
4. Connects to HPC nodes via SSH and runs `ps aux`
5. Correlates tasks with running processes
6. Generates HTML report with task status and process information

## API Versions

- **clickup_tasks**: ClickUp API v3 (team endpoint)
- **clicky**: ClickUp API v2 (list endpoint) - matches bash script

## Security

- Keep `.env` file secure (chmod 600)
- Add `.env` to .gitignore
- Use SSH keys instead of passwords when possible
- Command-line passwords are visible in process listings

## Dependencies

- **mjson**: Lightweight JSON parser (included)
- **libcurl**: HTTP client library
- **libssh**: SSH client library

## Credits

- **clicky**: Based on bash script by Serge Wielhouwer - GenomeScan B.V.
- **mjson**: https://github.com/cesanta/mjson
