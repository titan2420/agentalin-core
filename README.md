# Agentalin

**Agentalin** is a powerful Python-based job execution system designed for automating tasks across local and remote servers. It provides a flexible, configuration-driven approach to managing complex workflows, backups, deployments, and maintenance tasks.

## Features

- 🔐 **Secure Password Management**: Encrypted password storage with Fernet encryption
- 🌐 **Multi-Server Support**: Execute jobs on multiple remote servers via SSH
- 📋 **Job Scheduling**: Built-in interval-based job scheduling with execution tracking
- 🔄 **Multiple Actions**: Support for SSH commands, SCP transfers, HTTP requests (curl), compression, and safe-delete operations
- 📝 **Comprehensive Logging**: Detailed execution logs stored in `~/.agentalin/logs/`
- 🔧 **Variable Expansion**: Environment variable support for dynamic job configuration
- 🛡️ **Error Handling**: Configurable error handling with force-continue option
- 📦 **Safe Delete**: Automatic file deletion with expiration tracking

## Installation

### Prerequisites

- Python 3.8 or higher
- SSH access to remote servers (if using remote execution)
- `curl` command-line tool (for HTTP request actions)

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/agentalin.git
   cd agentalin
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Make the script executable (optional):**
   ```bash
   chmod +x agentalin.py
   ```

## Project Structure

```
agentalin/
├── agentalin.py          # Main script
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── servers/             # Server configuration files (JSON)
│   ├── server1.json
│   └── server2.json
├── jobs/                # Job configuration files (JSON)
│   ├── job1.json
│   └── job2.json
└── passwords/           # Encrypted password storage (auto-created)
    └── .master_key      # Encryption key (auto-created)
```

## Configuration

### Server Configuration

Create JSON files in the `servers/` directory to define your remote servers.

**Example (`servers/my-server.json`):**
```json
{
    "name": "my-server",
    "protocol": "ssh",
    "host": "192.168.1.100",
    "port": 22,
    "user": "username",
    "authentication": "system-key",
    "status": "active"
}
```

**Server Configuration Fields:**
- `name` (required): Unique identifier for the server
- `protocol` (required): Must be `"ssh"`
- `host` (required): Server hostname or IP address
- `port` (optional): SSH port (default: 22)
- `user` (required): SSH username
- `authentication` (required): Authentication method
  - `"system-key"`: Use SSH keys from `~/.ssh/`
  - `"password"`: Use password authentication (requires `password` or `password_name`)
- `password` (optional): Plain text password (not recommended)
- `password_name` (optional): Reference to a stored password (recommended)
- `status` (optional): `"active"` or `"disabled"` (default: active)

**Password Authentication Example:**
```json
{
    "name": "password-server",
    "protocol": "ssh",
    "host": "192.168.1.100",
    "port": 22,
    "user": "username",
    "authentication": "password",
    "password_name": "my_server_password",
    "status": "active"
}
```

### Job Configuration

Create JSON files in the `jobs/` directory to define your jobs.

**Basic Job Structure:**
```json
{
    "name": "my_job",
    "host": "my-server",
    "status": "active",
    "interval": 3600,
    "force": false,
    "routine": [
        "host: echo 'Hello from remote server'",
        "local: echo 'Hello from localhost'"
    ]
}
```

**Job Configuration Fields:**
- `name` (required): Unique job identifier
- `host` (optional): Default server for job execution (`"localhost"` or server name)
- `status` (optional): `"active"` or `"disabled"` (default: active)
- `interval` (optional): Minimum seconds between executions (default: 0, always execute)
- `force` (optional): Continue execution on errors (default: false)
- `routine` (required): Array of steps to execute

### Password Management

Store passwords securely using the built-in password manager:

```bash
python agentalin.py --add-password PASSWORD_NAME "your_password_here"
```

Passwords are encrypted and stored in the `passwords/` directory. They can be referenced in server configurations using `password_name` and accessed in jobs as environment variables (uppercase).

**Example:**
```bash
python agentalin.py --add-password DB_PASSWORD "secret123"
```

This password can be used in jobs as `${DB_PASSWORD}` or `$DB_PASSWORD`.

## Usage

### Basic Usage

**Execute all active jobs:**
```bash
python agentalin.py
```

**Execute a specific job:**
```bash
python agentalin.py /path/to/project job_name
```

**Execute with debug logging:**
```bash
python agentalin.py --debug
```

**Add a password:**
```bash
python agentalin.py --add-password PASSWORD_NAME "password_value"
```

### Command Syntax

```bash
python agentalin.py [BASE_PATH] [JOB_NAME] [OPTIONS]
```

- `BASE_PATH`: Optional path to project directory (default: current directory)
- `JOB_NAME`: Optional specific job to execute (default: all jobs)
- `--add-password PASS_NAME PASS`: Add a password to the secure store
- `--debug`: Enable debug logging to console

## Actions Reference

### SSH Command

Execute shell commands on local or remote hosts.

**String Syntax (Simple):**
```json
"host: command to execute"
"localhost: command to execute"
"local: command to execute"
"server-name: command to execute"
```

**Object Syntax (Advanced):**
```json
{
    "action": "ssh",
    "host": "my-server",
    "command": "ls -la /var/log",
    "print-output": true,
    "print-only-output": false
}
```

**Options:**
- `host`: Target server (`"localhost"`, `"local"`, or server name)
- `command`: Command to execute
- `print-output`: Print command output (default: true)
- `print-only-output`: Print only output without command info (default: false)

### SCP Transfer

Copy files between servers using SCP.

```json
{
    "action": "scp",
    "host": "localhost",
    "info": {
        "from": "my-server",
        "source": "/remote/path/file.txt",
        "destination": "/local/path/file.txt"
    }
}
```

**Fields:**
- `from`: Source server name
- `source`: Source file path
- `destination`: Destination file path

### HTTP Request (curl)

Make HTTP requests using curl.

```json
{
    "action": "curl",
    "host": "my-server",
    "info": {
        "url": "https://api.example.com/endpoint",
        "method": "POST",
        "headers": {
            "Authorization": "Bearer ${API_TOKEN}",
            "Content-Type": "application/json"
        },
        "body": {
            "key": "value",
            "timestamp": "${AGENTALIN_TIMESTAMP}"
        },
        "body_type": "json",
        "output": "/path/to/output.json"
    }
}
```

**Fields:**
- `url` (required): Request URL
- `method` (optional): HTTP method (default: GET)
- `headers` (optional): Request headers dictionary
- `body` (optional): Request body (dict or string)
- `body_type` (optional): `"json"`, `"form"`, or `"text"` (default: json)
- `output` (optional): Save response to file

### Compression

Compress files or directories using tar or zip.

```json
{
    "action": "compress",
    "type": "tar",
    "host": "my-server",
    "info": {
        "source": "/path/to/source",
        "destination": "/path/to/archive.tar.gz"
    },
    "ignore": [
        "/path/to/source/node_modules",
        "/path/to/source/.git"
    ]
}
```

**Fields:**
- `type`: `"tar"` or `"zip"`
- `source`: Source path to compress
- `destination`: Output archive path
- `ignore`: Array of paths to exclude

### Safe Delete

Move files to a safe-delete directory with expiration tracking. Files are automatically deleted after expiration.

```json
{
    "action": "safe-delete",
    "host": "my-server",
    "info": {
        "path": "/path/to/file.txt",
        "days": 30
    }
}
```

**Or using seconds:**
```json
{
    "action": "safe-delete",
    "host": "my-server",
    "info": {
        "path": "/path/to/file.txt",
        "expire": 2592000
    }
}
```

**Wildcard Support:**
```json
{
    "action": "safe-delete",
    "host": "my-server",
    "info": {
        "path": "/backups/*",
        "days": 7
    }
}
```

**Fields:**
- `path`: File or pattern to delete (supports `/*` for directory contents)
- `days`: Expiration in days
- `expire`: Expiration in seconds (alternative to `days`)

### Exit Command

Terminate job execution immediately.

```json
"exit"
```

Or in an SSH action:
```json
{
    "action": "ssh",
    "command": "exit"
}
```

## Variable Expansion

Agentalin supports environment variable expansion in commands and configurations:

- `${VARIABLE_NAME}` or `$VARIABLE_NAME`: Expand variable
- `$(command)`: Execute command and capture output

**Predefined Variables:**
- All stored passwords are available as uppercase variables (e.g., `${DB_PASSWORD}`)

**Example:**
```json
"host: TIMESTAMP=$(date +%s)"
"host: echo 'Backup created at ${TIMESTAMP}'"
```

## Job Scheduling

Jobs can be scheduled using the `interval` field (in seconds). The system tracks the last execution time and skips jobs that haven't reached their interval.

**Example:**
```json
{
    "name": "daily_backup",
    "interval": 86400,
    "routine": [...]
}
```

This job will only execute if at least 86400 seconds (24 hours) have passed since the last execution.

## Logging

All job executions are logged to `~/.agentalin/logs/` with timestamps:

```
~/.agentalin/logs/job_name_20240101_120000.log
```

Logs include:
- Execution start/end times
- All command outputs
- Error messages
- Step-by-step execution details

## Examples

### Example 1: Simple Backup Job

```json
{
    "name": "simple_backup",
    "host": "my-server",
    "routine": [
        "host: TIMESTAMP=$(date +%Y%m%d_%H%M%S)",
        {
            "action": "compress",
            "type": "tar",
            "host": "my-server",
            "info": {
                "source": "/var/www",
                "destination": "~/backups/www_${TIMESTAMP}.tar.gz"
            }
        },
        {
            "action": "scp",
            "host": "localhost",
            "info": {
                "from": "my-server",
                "source": "~/backups/www_${TIMESTAMP}.tar.gz",
                "destination": "~/local_backups/"
            }
        }
    ]
}
```

### Example 2: Database Backup with Cleanup

```json
{
    "name": "database_backup",
    "host": "db-server",
    "interval": 86400,
    "routine": [
        "host: BACKUP_FILE=backup_$(date +%Y%m%d).sql",
        "host: mysqldump -u ${DB_USER} -p${DB_PASSWORD} mydb > ${BACKUP_FILE}",
        {
            "action": "scp",
            "host": "localhost",
            "info": {
                "from": "db-server",
                "source": "${BACKUP_FILE}",
                "destination": "~/backups/"
            }
        },
        {
            "action": "safe-delete",
            "host": "db-server",
            "info": {
                "path": "${BACKUP_FILE}",
                "days": 7
            }
        }
    ]
}
```

### Example 3: API Health Check

```json
{
    "name": "health_check",
    "host": "localhost",
    "interval": 300,
    "routine": [
        {
            "action": "curl",
            "host": "localhost",
            "info": {
                "url": "https://api.example.com/health",
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer ${API_TOKEN}"
                }
            }
        }
    ]
}
```

## Security Considerations

1. **Password Storage**: Passwords are encrypted using Fernet (symmetric encryption). The master key is stored in `passwords/.master_key` with restrictive permissions (600).

2. **SSH Keys**: Prefer SSH key authentication over passwords when possible.

3. **File Permissions**: Ensure server and job configuration files have appropriate permissions.

4. **Logs**: Logs may contain sensitive information. Secure the `~/.agentalin/logs/` directory.

5. **Safe Delete**: Files moved to safe-delete are not immediately deleted. Ensure proper cleanup.

## Troubleshooting

### Connection Issues

- Verify SSH connectivity: `ssh user@host`
- Check server configuration JSON syntax
- Ensure SSH keys are properly configured for `system-key` authentication
- Verify password is correctly stored if using password authentication

### Job Not Executing

- Check job `status` is `"active"`
- Verify `interval` hasn't been reached (check `~/.agentalin/last_executions/`)
- Review logs in `~/.agentalin/logs/`

### Variable Expansion Issues

- Ensure variables are defined before use
- Use `${VAR}` syntax for clarity
- Check password names match exactly (case-sensitive)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[Specify your license here]

## Author

[Your name/username]

---

For more information, issues, or feature requests, please visit the [GitHub repository](https://github.com/yourusername/agentalin).

