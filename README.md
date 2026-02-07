# C ClickUp Tasks

A simple C command-line tool to fetch and display ClickUp tasks, with support for monitoring running jobs on HPC nodes via SSH.

## Features

- Fetch and display ClickUp tasks in a formatted table
- Monitor running jobs on HPC nodes using SSH
- Filter jobs by name/pattern using ps command
- Uses lightweight mjson library for JSON parsing
- Built with libcurl and libssh

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

To compile the project, simply run the `make` command in the project's root directory:

```bash
make
```

This will generate an executable file named `clickup_tasks`.

## Usage

### List ClickUp Tasks

To run the program in default mode (list ClickUp tasks), you need to set the following environment variables with your ClickUp credentials:

*   `CLICKUP_TOKEN`: Your personal ClickUp API token.
*   `CLICKUP_USERID`: Your numeric user ID.
*   `CLICKUP_TEAMID`: The ID of the team/workspace you want to fetch tasks from.

You can set them and run the executable like this:

```bash
export CLICKUP_TOKEN="your_api_token"
export CLICKUP_USERID="your_user_id"
export CLICKUP_TEAMID="your_team_id"

./clickup_tasks
```

### Monitor Jobs on HPC Nodes

To monitor running jobs on HPC nodes using SSH:

```bash
./clickup_tasks -m -n "node1:22,node2:22" -u username -p password
```

Options:
- `-m`: Enable monitor mode
- `-n NODES`: Comma-separated list of nodes in format `hostname:port`
- `-u USERNAME`: SSH username
- `-p PASSWORD`: SSH password (WARNING: visible in process listings and shell history)
- `-f FILTER`: Optional filter to search for specific jobs (alphanumeric, `-`, `_`, `.`, `/` only)
- `-h`: Show help message

**Security Warning**: Command-line passwords are visible in process listings and shell history. For production use, consider:
- Using SSH keys for authentication instead of passwords
- Storing credentials in a secure configuration file
- Prompting for passwords interactively

Examples:

```bash
# Monitor all jobs on two nodes
./clickup_tasks -m -n "node1:22,node2:22" -u admin -p secret

# Monitor only Python jobs on a single node
./clickup_tasks -m -n "node1:22" -u admin -p secret -f "python"

# Monitor jobs matching a specific pattern
./clickup_tasks -m -n "node1:22" -u admin -p secret -f "job_name"
```

## API Version

This tool uses the ClickUp API v3. The API endpoint is:
```
https://api.clickup.com/api/v3/team/{team_id}/task
```

## Dependencies

- **mjson**: Lightweight JSON parser (included in source)
- **libcurl**: HTTP client library
- **libssh**: SSH client library
