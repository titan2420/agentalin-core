#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import paramiko
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
    """Manages secure storage and retrieval of passwords"""
    
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.passwords_dir = base_path / "passwords"
        self.passwords_dir.mkdir(parents=True, exist_ok=True)
        self.key_file = self.passwords_dir / ".master_key"
        self._fernet = self._get_or_create_fernet()
    
    def _get_or_create_fernet(self) -> Fernet:
        """Get or create the Fernet encryption key"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            # Generate a new key
            key = Fernet.generate_key()
            # Store it securely (only readable by owner)
            with open(self.key_file, 'wb') as f:
                f.write(key)
            os.chmod(self.key_file, 0o600)
        
        return Fernet(key)
    
    def add_password(self, name: str, password: str) -> bool:
        """Add or update a password with the given name"""
        try:
            # Encrypt the password
            encrypted_password = self._fernet.encrypt(password.encode('utf-8'))
            
            # Store in a file named after the password name
            password_file = self.passwords_dir / f"{name}.enc"
            with open(password_file, 'wb') as f:
                f.write(encrypted_password)
            
            # Set restrictive permissions
            os.chmod(password_file, 0o600)
            
            return True
        except Exception as e:
            logging.error(f"Failed to add password '{name}': {e}")
            return False
    
    def get_password(self, name: str) -> Optional[str]:
        """Retrieve and decrypt a password by name"""
        try:
            password_file = self.passwords_dir / f"{name}.enc"
            if not password_file.exists():
                return None
            
            with open(password_file, 'rb') as f:
                encrypted_password = f.read()
            
            # Decrypt the password
            decrypted_password = self._fernet.decrypt(encrypted_password)
            return decrypted_password.decode('utf-8')
        except Exception as e:
            logging.warning(f"Failed to retrieve password '{name}': {e}")
            return None
    
    def list_passwords(self) -> List[str]:
        """List all stored password names"""
        passwords = []
        for password_file in self.passwords_dir.glob("*.enc"):
            name = password_file.stem
            passwords.append(name)
        return sorted(passwords)
    
    def load_all_passwords(self) -> Dict[str, str]:
        """Load all passwords and return as a dictionary"""
        passwords = {}
        for name in self.list_passwords():
            password = self.get_password(name)
            if password:
                passwords[name] = password
        return passwords


class SSHClient:
    def __init__(self, server_config: Dict[str, Any], password_manager: Optional[PasswordManager] = None):
        self.config = server_config
        self.password_manager = password_manager
        self.client: Optional[paramiko.SSHClient] = None
        self._connect()
    
    def _connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            auth_type = self.config.get("authentication", "system-key")
            
            if auth_type == "system-key":
                self.client.connect(
                    hostname=self.config["host"],
                    port=self.config.get("port", 22),
                    username=self.config["user"],
                    look_for_keys=True,
                    allow_agent=True
                )
            elif auth_type == "password":
                password = None
                # Check if password is specified directly in config
                if "password" in self.config:
                    password = self.config["password"]
                # Check if password_name is specified to load from PasswordManager
                elif "password_name" in self.config and self.password_manager:
                    password = self.password_manager.get_password(self.config["password_name"])
                    if password is None:
                        raise ValueError(f"Password '{self.config['password_name']}' not found in password store")
                else:
                    raise ValueError("Password authentication requires either 'password' or 'password_name' in server config")
                
                self.client.connect(
                    hostname=self.config["host"],
                    port=self.config.get("port", 22),
                    username=self.config["user"],
                    password=password
                )
            else:
                raise ValueError(f"Unsupported authentication: {auth_type}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.config['host']}: {e}")
    
    def execute(self, command: str) -> Tuple[str, str, int]:
        if not self.client:
            self._connect()
        
        stdin, stdout, stderr = self.client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        return output, error, exit_status
    
    def close(self):
        if self.client:
            self.client.close()
            self.client = None


class JobExecutor:    
    def __init__(self, base_path: Optional[str] = None, debug: bool = False):
        if base_path:
            self.base_path = Path(base_path).resolve()
        else:
            self.base_path = Path.cwd()
        
        home_path = Path(os.path.expanduser("~")).resolve()

        self.password_manager = PasswordManager(self.base_path)
        self.servers = self._load_servers()
        self.jobs = self._load_jobs()
        self.log_dir = home_path / ".agentalin" / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.last_executions_dir = home_path / ".agentalin" / "last_executions"
        self.last_executions_dir.mkdir(parents=True, exist_ok=True)
        self.debug = debug
    
    def _load_servers(self) -> Dict[str, SSHClient]:
        """Load all server configurations from servers/ folder and initialize active ones"""
        servers_dir = self.base_path / "servers"
        servers = {}
        
        if not servers_dir.exists():
            return servers
        
        for server_file in servers_dir.glob("*.json"):
            try:
                with open(server_file, 'r') as f:
                    server_config = json.load(f)
                
                # Check if server is disabled
                if server_config.get("status") == "disabled":
                    continue
                
                # Only initialize SSH servers
                if server_config.get("protocol") == "ssh":
                    servers[server_config["name"]] = SSHClient(server_config, self.password_manager)
            except Exception as e:
                logging.warning(f"Failed to load server from {server_file}: {e}")
        
        return servers
    
    def _load_jobs(self) -> List[Dict[str, Any]]:
        """Load all job configurations from jobs/ folder"""
        jobs_dir = self.base_path / "jobs"
        jobs = []
        
        if not jobs_dir.exists():
            return jobs
        
        for job_file in jobs_dir.glob("*.json"):
            try:
                with open(job_file, 'r') as f:
                    job_data = json.load(f)
                
                # Handle both single job object and array of jobs
                if isinstance(job_data, dict):
                    # Single job object
                    if "name" in job_data or "routine" in job_data:
                        jobs.append(job_data)
                    # Could be a jobs array wrapper
                    elif "jobs" in job_data:
                        jobs.extend(job_data["jobs"])
                    else:
                        logging.warning(f"Invalid job file format in {job_file}: expected job object or jobs array")
                elif isinstance(job_data, list):
                    # Array of jobs
                    jobs.extend(job_data)
                else:
                    logging.warning(f"Invalid job file format in {job_file}: expected object or array")
            except Exception as e:
                logging.warning(f"Failed to load job from {job_file}: {e}")
        
        return jobs
    
    def _expand_variables(self, text: str, env_vars: Dict[str, str]) -> str:
        result = text
        for key, value in env_vars.items():
            result = result.replace(f"${{{key}}}", value)
            result = result.replace(f"${key}", value)
        return result
    
    def _execute_local_command(self, command: str, env_vars: Dict[str, str]) -> Tuple[str, int]:
        if '=' in command and not command.strip().startswith('#'):
            parts = command.split('=', 1)
            if len(parts) == 2 and ' ' not in parts[0].strip():
                var_name = parts[0].strip()
                var_value = parts[1].strip()
                # Execute the value (e.g., $(date +%s)) and capture result
                if var_value.startswith('$(') and var_value.endswith(')'):
                    cmd_to_exec = var_value[2:-1]  # Remove $()
                    result = subprocess.run(
                        cmd_to_exec,
                        shell=True,
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        env_vars[var_name] = result.stdout.strip()
                    return result.stdout + result.stderr, result.returncode
                else:
                    env_vars[var_name] = self._expand_variables(var_value, env_vars)
                    return "", 0
        
        expanded_cmd = self._expand_variables(command, env_vars)
        result = subprocess.run(
            expanded_cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout + result.stderr, result.returncode
    
    def _execute_host_command(self, server_name: str, command: str, env_vars: Dict[str, str]) -> Tuple[str, int]:
        if server_name not in self.servers:
            raise ValueError(f"Server '{server_name}' not found")
        
        # Handle variable assignment (VAR=value)
        if '=' in command and not command.strip().startswith('#'):
            parts = command.split('=', 1)
            if len(parts) == 2 and ' ' not in parts[0].strip():
                var_name = parts[0].strip()
                var_value = parts[1].strip()
                # Execute the value (e.g., $(date +%s)) and capture result
                if var_value.startswith('$(') and var_value.endswith(')'):
                    cmd_to_exec = var_value[2:-1]  # Remove $()
                    cmd_output, cmd_error, cmd_exit = self.servers[server_name].execute(cmd_to_exec)
                    if cmd_exit == 0:
                        env_vars[var_name] = cmd_output.strip()
                    return cmd_output + cmd_error, cmd_exit
                else:
                    env_vars[var_name] = self._expand_variables(var_value, env_vars)
                    return "", 0
        
        expanded_cmd = self._expand_variables(command, env_vars)
        output, error, exit_status = self.servers[server_name].execute(expanded_cmd)
        return output + error, exit_status
    
    def _build_curl_command(self, info: Dict[str, Any], env_vars: Dict[str, str]) -> str:
        """Build a curl command from info dictionary"""
        url = self._expand_variables(str(info.get("url", "")), env_vars)
        method = info.get("method", "GET").upper()
        headers = info.get("headers", {})
        body = info.get("body")
        body_type = info.get("body_type", "json")
        output = info.get("output")
        
        # Start building curl command
        cmd_parts = ["curl", "-s", "-S"]  # -s silent, -S show errors
        
        # Add method
        if method != "GET":
            cmd_parts.extend(["-X", method])
        
        # Add headers
        for header_name, header_value in headers.items():
            expanded_value = self._expand_variables(str(header_value), env_vars)
            cmd_parts.extend(["-H", f"{header_name}: {expanded_value}"])
        
        # Add body
        if body is not None:
            if body_type == "json":
                # Expand variables in body dict values before converting to JSON
                expanded_body = body
                if isinstance(body, dict):
                    expanded_body = {
                        k: self._expand_variables(str(v), env_vars) if isinstance(v, str) else v
                        for k, v in body.items()
                    }
                elif isinstance(body, str):
                    expanded_body = self._expand_variables(body, env_vars)
                # Convert body to JSON string
                body_json = json.dumps(expanded_body)
                cmd_parts.extend(["-H", "Content-Type: application/json"])
                cmd_parts.extend(["-d", body_json])
            elif body_type == "form":
                if isinstance(body, dict):
                    form_data = "&".join([f"{k}={v}" for k, v in body.items()])
                    form_data = self._expand_variables(form_data, env_vars)
                    cmd_parts.extend(["-d", form_data])
                else:
                    body_str = self._expand_variables(str(body), env_vars)
                    cmd_parts.extend(["-d", body_str])
            # text body:
            else:
                body_str = self._expand_variables(str(body), env_vars)
                cmd_parts.extend(["-d", body_str])
        
        # Add output file
        if output:
            expanded_output = self._expand_variables(str(output), env_vars)
            cmd_parts.extend(["-o", expanded_output])
        
        # Add URL
        cmd_parts.append(url)
        
        # Properly quote arguments that need it
        quoted_parts = []
        for part in cmd_parts:
            if any(char in part for char in [' ', '&', '|', ';', '$', '`', '"', "'"]):
                quoted_parts.append(shlex.quote(part))
            else:
                quoted_parts.append(part)
        
        return " ".join(quoted_parts)
    
    def _handle_safe_delete(self, info: Dict[str, Any], host: Optional[str], env_vars: Dict[str, str], logger: logging.Logger) -> Tuple[str, int]:
        """Handle safe-delete action: move file to safe-deletes directory with expiration tracking"""
        file_path = self._expand_variables(str(info.get("path", "")), env_vars)
        days = info.get("days")
        expire_seconds = info.get("expire")
        
        # Check if path ends with /* to handle folder/* pattern
        if len(file_path) >= 2 and file_path[-2:] == "/*":
            # Remove /* to get directory path
            directory_path = file_path[:-2]
            logger.info(f"Safe-delete pattern detected for folder: {directory_path}")
            
            # List all files in the directory
            use_find = True
            if host == "localhost" or host is None:
                list_output, list_exit = self._execute_local_command(f"find {directory_path} -maxdepth 1 -type f", env_vars)
            else:
                list_output, list_exit = self._execute_host_command(host, f"find {directory_path} -maxdepth 1 -type f", env_vars)
            
            # Fallback to ls if find doesn't work
            if list_exit != 0:
                use_find = False
                if host == "localhost" or host is None:
                    list_output, list_exit = self._execute_local_command(f"ls -1 {directory_path}/ 2>/dev/null || true", env_vars)
                else:
                    list_output, list_exit = self._execute_host_command(host, f"ls -1 {directory_path}/ 2>/dev/null || true", env_vars)
            
            all_output = []
            all_exit_code = 0
            
            if list_exit == 0 and list_output.strip():
                # Parse files and process each one
                files = [f.strip() for f in list_output.strip().split('\n') if f.strip()]
                
                # If using ls, prepend directory path to each filename
                if not use_find:
                    files = [f"{directory_path.rstrip('/')}/{f}" if not f.startswith('/') else f for f in files]
                
                logger.info(f"Found {len(files)} file(s) in {directory_path}")
                
                for file_item in files:
                    # Create new info dict for each file
                    file_info = info.copy()
                    file_info["path"] = file_item
                    
                    # Recursively call _handle_safe_delete for each file
                    logger.debug(f"Processing file: {file_item}")
                    output, exit_code = self._handle_safe_delete(file_info, host, env_vars, logger)
                    all_output.append(output)
                    if exit_code != 0:
                        all_exit_code = exit_code
            else:
                logger.warning(f"No files found in directory: {directory_path}")
                all_output.append(f"No files found in directory: {directory_path}")
            
            return "\n".join(all_output), all_exit_code
        
        # Convert days to seconds if provided, otherwise use expire_seconds
        if days is not None:
            expiration_seconds = int(days) * 86400
        elif expire_seconds is not None:
            expiration_seconds = int(expire_seconds)
        else:
            raise ValueError("Either 'days' or 'expire' must be specified in safe-delete info")
        

        # Get current timestamp
        current_timestamp = int(time.time())
        expiration_timestamp = current_timestamp + expiration_seconds
        
        # Safe deletes directory
        
        all_output = []
        all_exit_code = 0
        
        # Step 1: Create safe-deletes directory
        logger.debug(f"Creating directory: ~/.agentalin/safe-deletes")
        if host == "localhost" or host is None:
            output, exit_code = self._execute_local_command(f"mkdir -p ~/.agentalin/safe-deletes", env_vars)
        else:
            output, exit_code = self._execute_host_command(host, f"mkdir -p ~/.agentalin/safe-deletes", env_vars)
        all_output.append(output)
        if exit_code != 0:
            all_exit_code = exit_code
        
        
        
        # Step 3: Get basename of file
        file_basename = file_path.replace("/", "_")
        new_filename = f"{file_basename}.{current_timestamp}.{expiration_timestamp}"    
        new_file_path = f"~/.agentalin/safe-deletes/{new_filename}"
        
        # Step 4: Check if file exists and move it
        logger.debug(f"Moving file {file_path} to ~/.agentalin/safe-deletes/{new_filename}")
        if host == "localhost" or host is None:
            # Check if file exists
            check_output, check_exit = self._execute_local_command(f"test -f {file_path}", env_vars)
            if check_exit == 0:
                output, exit_code = self._execute_local_command(f"mv {file_path} ~/.agentalin/safe-deletes/{new_filename}", env_vars)
                all_output.append(output)
                if exit_code != 0:
                    all_exit_code = exit_code
            else:
                logger.warning(f"File not found: {file_path}")
                all_output.append(f"File not found: {file_path}")
        else:
            # Check if file exists
            check_output, check_exit = self._execute_host_command(host, f"test -f {file_path}", env_vars)
            if check_exit == 0:
                output, exit_code = self._execute_host_command(host, f"mv {file_path} {new_file_path}", env_vars)
                all_output.append(output)
                if exit_code != 0:
                    all_exit_code = exit_code
            else:
                logger.warning(f"File not found: {file_path}")
                all_output.append(f"File not found: {file_path}")
        
        # Step 5: List all files in safe-deletes directory to check for expiration
        logger.debug("Checking for expired files in ~/.agentalin/safe-deletes")
        if host == "localhost" or host is None:
            list_output, list_exit = self._execute_local_command(f"find ~/.agentalin/safe-deletes -maxdepth 1 -type f -name '*.*.*' -printf '%f\\n'", env_vars)
        else:
            list_output, list_exit = self._execute_host_command(host, f"find ~/.agentalin/safe-deletes -maxdepth 1 -type f -name '*.*.*' -printf '%f\\n'", env_vars)
        
        # Fallback to ls if find doesn't work
        if list_exit != 0:
            if host == "localhost" or host is None:
                list_output, list_exit = self._execute_local_command(f"ls -1 ~/.agentalin/safe-deletes/ 2>/dev/null | grep -v '^hell-' || true", env_vars)
            else:
                list_output, list_exit = self._execute_host_command(host, f"ls -1 ~/.agentalin/safe-deletes/ 2>/dev/null | grep -v '^hell-' || true", env_vars)
        
        if list_exit == 0 and list_output.strip():
            # Parse files and check expiration
            files = [f.strip() for f in list_output.strip().split('\n') if f.strip() and not f.strip().startswith('hell-')]
            for filename in files:
                # Check if filename matches pattern: name.timestamp.expiration
                parts = filename.rsplit('.', 2)
                if len(parts) == 3:
                    try:
                        file_expiration = int(parts[2])
                        if file_expiration < current_timestamp:
                            # Step 2: Create hell directory
                            logger.debug("Creating directory: " + ("~/.agentalin/safe-deletes/hell-" + str(current_timestamp)))
                            if host == "localhost" or host is None:
                                output, exit_code = self._execute_local_command(f"mkdir -p ~/.agentalin/safe-deletes/hell-{current_timestamp}", env_vars)
                            else:
                                output, exit_code = self._execute_host_command(host, f"mkdir -p ~/.agentalin/safe-deletes/hell-{current_timestamp}", env_vars)
                            all_output.append(output)
                            if exit_code != 0:
                                all_exit_code = exit_code

                            # File is expired, move to hell directory
                            expired_file_path = f"~/.agentalin/safe-deletes/{filename}"
                            logger.debug(f"Moving expired file {expired_file_path} to ~/.agentalin/safe-deletes/hell-{current_timestamp}")
                            if host == "localhost" or host is None:
                                output, exit_code = self._execute_local_command(f"mv {expired_file_path} ~/.agentalin/safe-deletes/hell-{current_timestamp}/", env_vars)
                            else:
                                output, exit_code = self._execute_host_command(host, f"mv {expired_file_path} ~/.agentalin/safe-deletes/hell-{current_timestamp}/", env_vars)
                            all_output.append(output)
                            if exit_code != 0:
                                all_exit_code = exit_code
                    except ValueError:
                        # Filename doesn't match expected pattern, skip
                        continue
        
        # Step 6: Delete all files in hell directory
        logger.debug("Deleting files in ~/.agentalin/safe-deletes/hell-" + str(current_timestamp))
        if host == "localhost" or host is None:
            output, exit_code = self._execute_local_command(f"rm -rf ~/.agentalin/safe-deletes/hell-{current_timestamp}/*", env_vars)
        else:
            output, exit_code = self._execute_host_command(host, f"rm -rf ~/.agentalin/safe-deletes/hell-{current_timestamp}/*", env_vars)
        all_output.append(output)
        if exit_code != 0:
            all_exit_code = exit_code
        
        
        return "\n".join(all_output), all_exit_code
    
    def _build_compress_command(self, compress_type: str, source: str, destination: str, ignore_list: List[str], env_vars: Dict[str, str]) -> str:
        """Build a compression command (tar or zip) from parameters"""
        expanded_source = self._expand_variables(source, env_vars)
        expanded_destination = self._expand_variables(destination, env_vars)
        
        if compress_type == "tar":
            # Build tar command with gzip compression
            cmd_parts = ["tar", "-czf", expanded_destination]
            
            source_normalized = expanded_source.rstrip('/')
            source_dir = None
            source_name = None
            
            # Determine if we should use -C for cleaner archive structure
            if source_normalized:
                source_dir = os.path.dirname(source_normalized) if os.path.dirname(source_normalized) else None
                source_name = os.path.basename(source_normalized) if os.path.basename(source_normalized) else None
                
                # Use -C only if we have a valid parent directory
                use_c_flag = source_dir and source_dir != '/' and source_name
            else:
                use_c_flag = False
            
            # Add exclude patterns
            for ignore_path in ignore_list:
                expanded_ignore = self._expand_variables(ignore_path, env_vars)
                
                if use_c_flag:
                    # Convert absolute exclude paths to relative paths when using -C
                    # When using -C, files are archived with source_name as the root, so exclude patterns
                    # should be relative to the archive root (which includes source_name)
                    if expanded_ignore.startswith(source_dir):
                        # Remove source_dir prefix
                        relative_path = expanded_ignore[len(source_dir):].lstrip('/')
                        # Keep source_name in the path since it's the archive root
                        # relative_path should already start with source_name/ or be source_name
                        if relative_path == source_name:
                            # Exclude the entire source directory
                            relative_path = '.'
                        
                        # remove last / 
                        if relative_path.endswith('/'):
                            relative_path = relative_path.rstrip('/')

                        # Otherwise keep relative_path as-is (it already includes source_name/)
                        cmd_parts.extend(["--exclude", relative_path])
                    else:
                        # Keep as-is if it doesn't match the pattern
                        cmd_parts.extend(["--exclude", expanded_ignore])
                else:
                    # Use absolute paths when not using -C
                    cmd_parts.extend(["--exclude", expanded_ignore])
            
            # Add source directory
            if use_c_flag:
                cmd_parts.extend(["-C", source_dir, source_name])
            else:
                cmd_parts.append(source_normalized if source_normalized else expanded_source)
            
        elif compress_type == "zip":
            # Build zip command
            cmd_parts = ["zip", "-r", expanded_destination, expanded_source]
            
            # Add exclude patterns
            for ignore_path in ignore_list:
                expanded_ignore = self._expand_variables(ignore_path, env_vars)
                # For zip, we need to use -x flag with relative paths
                # Remove the source prefix if present
                if expanded_ignore.startswith(expanded_source.rstrip('/')):
                    relative_ignore = expanded_ignore[len(expanded_source.rstrip('/')):].lstrip('/')
                else:
                    relative_ignore = expanded_ignore
                cmd_parts.extend(["-x", f"{relative_ignore}*"])
        else:
            raise ValueError(f"Unsupported compression type: {compress_type}")
        
        # Properly quote arguments that need it
        quoted_parts = []
        for part in cmd_parts:
            if any(char in part for char in [' ', '&', '|', ';', '$', '`', '"', "'"]):
                quoted_parts.append(shlex.quote(part))
            else:
                quoted_parts.append(part)

        return " ".join(quoted_parts)
    
    def _setup_job_logger(self, job_name: str) -> logging.Logger:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"{job_name}_{timestamp}.log"
        
        logger = logging.getLogger(f"job_{job_name}_{timestamp}")
        logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers to avoid duplicates
        logger.handlers = []
        
        # File handler
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler (for stdout/stderr)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if self.debug else logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _get_last_execution_time(self, job_name: str) -> Optional[float]:
        execution_file = self.last_executions_dir / f"{job_name}.json"
        
        if not execution_file.exists():
            return None
        
        try:
            with open(execution_file, 'r') as f:
                data = json.load(f)
                return data.get("last_execution_time")
        except Exception as e:
            logging.warning(f"Failed to read last execution time for {job_name}: {e}")
            return None
    
    def _save_last_execution_time(self, job_name: str, execution_time: float):
        execution_file = self.last_executions_dir / f"{job_name}.json"
        
        try:
            data = {
                "last_execution_time": execution_time,
                "last_execution_datetime": datetime.fromtimestamp(execution_time).isoformat()
            }
            with open(execution_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.warning(f"Failed to save last execution time for {job_name}: {e}")
    
    def _should_execute_job(self, job: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        interval = job.get("interval", 0)
        
        job_name = job.get("name", "unknown")
        last_execution = self._get_last_execution_time(job_name)
        
        if last_execution is None:
            # No previous execution, should execute
            return True, None
        
        current_time = time.time()
        time_since_last = current_time - last_execution
        
        if time_since_last >= interval:
            return True, None
        else:
            remaining = interval - time_since_last
            hours_remaining = remaining / 3600
            return False, f"Interval not yet passed. {hours_remaining:.2f} hours remaining"
    
    def execute_job(self, job: Dict[str, Any]) -> bool:
        if job.get("status") == "disabled":
            return False

        job_name = job.get("name", "unknown")
        logger = self._setup_job_logger(job_name)
        
        logger.info(f"Starting execution of job: {job_name} ")
        logger.info(f"=" * 80)

        
        should_execute, reason = self._should_execute_job(job)
        if not should_execute:
            logger.info(f"Skipping job '{job_name}': {reason}")
            logger.info(f"-" * 80 + "\n")
            return False
        
        # Load passwords into environment variables
        env_vars = {}
        passwords = self.password_manager.load_all_passwords()
        for pass_name, pass_value in passwords.items():
            # Make passwords available as ${PASS_NAME} variables
            env_vars[pass_name.upper()] = pass_value
        
        host_server = job.get("host", "localhost")
        force_continue = job.get("force", False)
        

        if host_server and host_server != "localhost" and host_server not in self.servers:
            logger.error(f"Server '{host_server}' not found")
            return False
        
        routine = job.get("routine", [])
        success = True
        step_number = 0
        
        for step in routine:
            step_number += 1
            host = host_server
            executive_step = None
            try:
                if isinstance(step, str):
                    if step == "exit":
                        logger.info(f"[Step {step_number}] job terminated by exit command")
                        logger.info(f"-" * 80 + "\n")
                        return False
                    
                    # Determine host for this step (use local variable to avoid modifying global host_server)
                    step_host = host_server
                    if ":" in step:
                        server_name, command = step.split(":", 1)
                        server_name = server_name.strip()
                        command = command.strip()
                        if server_name in self.servers:
                            step_host = server_name
                        elif server_name == "localhost" or server_name == 'local':
                            step_host = "localhost"
                        elif server_name == "host":
                            # Use the job-level host_server
                            step_host = host_server
                        else:
                            # Unknown server name, use job-level host_server
                            step_host = host_server
                    else:
                        command = step.strip()

                    executive_step = {
                        "action": "ssh",
                        "host": step_host,
                        "command": command,
                    }
                
                elif isinstance(step, dict):
                    executive_step = step

                host = executive_step.get("host")
                action = executive_step.get("action")
                
                if action == "scp":
                    info = executive_step.get("info", {})
                    from_server = info.get("from")
                    source = info.get("source", "")
                    destination = info.get("destination", "")
                    logger.info(f"[Step {step_number}] {from_server}:{source} -> {host}:{destination}")

                    command = f"scp -P {self.servers[from_server].config.get('port', 22)} {self.servers[from_server].config['user']}@{self.servers[from_server].config['host']}:{source} {destination}"

                    if host == "localhost":
                        output, exit_code = self._execute_local_command(command, env_vars)
                    else:
                        output, exit_code = self._execute_host_command(host, command, env_vars)

                    if output:
                        logger.debug(f"SCP output:\n{output}")
                    
                    if exit_code != 0:
                        logger.error(f"SCP transfer failed with exit code {exit_code}")
                        if output:
                            logger.error(f"Error output:\n{output}")
                        success = False
                        if not force_continue:
                            logger.error(f"Stopping execution due to error (force is not enabled)")
                            break
                
                elif action == "curl":
                    info = executive_step.get("info", {})
                    url = info.get("url", "")
                    output_file = info.get("output")
                    logger.info(f"[Step {step_number}] Executing curl request: {url}")
                    
                    
                    # Build curl command
                    curl_command = self._build_curl_command(info, env_vars)
                    
                    # Execute curl on specified host
                    if host == "localhost" or host is None:
                        output, exit_code = self._execute_local_command(curl_command, env_vars)
                    else:
                        output, exit_code = self._execute_host_command(host, curl_command, env_vars)
                    
                    if output:
                        logger.debug(f"Curl output:\n{output}")
                    
                    if exit_code != 0:
                        logger.error(f"Curl request failed with exit code {exit_code}")
                        if output:
                            logger.error(f"Error output:\n{output}")
                        success = False
                        if not force_continue:
                            logger.error(f"Stopping execution due to error (force is not enabled)")
                            break
                
                elif action == "compress":
                    compress_type = executive_step.get("type", "tar")
                    info = executive_step.get("info", {})
                    source = info.get("source", "")
                    destination = info.get("destination", "")
                    ignore_list = executive_step.get("ignore", [])
                    
                    # Determine execution host
                    compress_host = executive_step.get("host")
                    if compress_host is None:
                        compress_host = host_server
                    
                    logger.info(f"[Step {step_number}] '{compress_host}': {compress_type} {source} -> {destination}")
                    if ignore_list:
                        logger.debug(f"Ignoring paths: {', '.join(ignore_list)}")
                    
                    # Build compress command
                    compress_command = self._build_compress_command(compress_type, source, destination, ignore_list, env_vars)
                    
                    # Execute compress on specified host
                    if compress_host == "localhost" or compress_host is None:
                        output, exit_code = self._execute_local_command(compress_command, env_vars)
                    else:
                        output, exit_code = self._execute_host_command(compress_host, compress_command, env_vars)
                    
                    if output:
                        logger.debug(f"Compress output:\n{output}")
                    
                    if exit_code != 0:
                        logger.error(f"Compression failed with exit code {exit_code}")
                        if output:
                            logger.error(f"Error output:\n{output}")
                        success = False
                        if not force_continue:
                            logger.error(f"Stopping execution due to error (force is not enabled)")
                            break
                
                elif action == "ssh":
                    # Get command from executive_step
                    command = executive_step.get("command", "")
                    if not command:
                        logger.error(f"[Step {step_number}] SSH action requires 'command' field")
                        success = False
                        if not force_continue:
                            logger.error(f"Stopping execution due to error (force is not enabled)")
                            break
                    else:
                        if command == "exit":
                            logger.info(f"[Step {step_number}] job terminated by exit command")
                            logger.info(f"-" * 80 + "\n")
                            return False
                        
                        # Get print options
                        print_output = executive_step.get("print-output", True)
                        print_only_output = executive_step.get("print-only-output", False)
                        
                        # Determine execution host
                        ssh_host = executive_step.get("host")
                        if ssh_host is None:
                            ssh_host = host_server
                        
                        # Log execution info only if not print-only-output mode
                        if not print_only_output:
                            logger.info(f"[Step {step_number}] '{ssh_host}': {command}")
                        
                        # Execute SSH command
                        if ssh_host == "localhost" or ssh_host is None:
                            output, exit_code = self._execute_local_command(command, env_vars)
                        else:
                            output, exit_code = self._execute_host_command(ssh_host, command, env_vars)
                        
                        # Handle output printing based on options
                        if print_output and output:
                            if print_only_output:
                                # In print-only mode, use info level to ensure it's visible
                                logger.info(output.rstrip())
                            else:
                                logger.debug(f"SSH command output:\n{output}")
                        
                        if exit_code != 0:
                            logger.error(f"SSH command failed with exit code {exit_code}: {command}")
                            if output:
                                logger.error(f"Error output:\n{output}")
                            success = False
                            if not force_continue:
                                if not print_only_output:
                                    logger.error(f"Stopping execution due to error (force is not enabled)")
                                break
                
                elif action == "safe-delete":
                    info = executive_step.get("info", {})
                    file_path = info.get("path", "")
                    
                    # Determine execution host
                    safe_delete_host = executive_step.get("host")
                    if safe_delete_host is None:
                        safe_delete_host = host_server
                    
                    logger.info(f"[Step {step_number}] '{safe_delete_host}': safe-delete {file_path}")
                    
                    # Execute safe-delete
                    output, exit_code = self._handle_safe_delete(info, safe_delete_host, env_vars, logger)
                    
                    if output:
                        logger.debug(f"Safe-delete output:\n{output}")
                    
                    if exit_code != 0:
                        logger.error(f"Safe-delete failed with exit code {exit_code}")
                        if output:
                            logger.error(f"Error output:\n{output}")
                        success = False
                        if not force_continue:
                            logger.error(f"Stopping execution due to error (force is not enabled)")
                            break
                
                else:
                    logger.error(f"[Step {step_number}] Unknown action: {action}")
                    success = False
                    if not force_continue:
                        logger.error(f"Stopping execution due to error (force is not enabled)")
                        break
            
            except Exception as e:
                logger.exception(f"[Step {step_number}] Error executing step: {e}")
                success = False
                if not force_continue:
                    logger.error(f"Stopping execution due to error (force is not enabled)")
                    break
        
        if success:
            logger.info(f"Job: {job_name} - Completed successfully")
            execution_time = time.time()
            self._save_last_execution_time(job_name, execution_time)
        else:
            logger.warning(f"Job: {job_name} - Completed with errors")
        logger.info(f"-" * 80 + "\n")
        
        # Clean up logger handlers
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        return success
    
    def execute(self, job_name: Optional[str] = None):
        jobs = self.jobs
        
        if job_name:
            logger = self._setup_job_logger(job_name)
            jobs = [j for j in jobs if j.get("name") == job_name]
            if not jobs:
                logger.error(f"Job '{job_name}' not found")
                return
        
        for job in jobs:
            self.execute_job(job)
    
    def close(self):
        for server in self.servers.values():
            server.close()


def main():
    parser = argparse.ArgumentParser(description='Agentalin - Job execution system')
    parser.add_argument('base_path', nargs='?', help='Base path for the project')
    parser.add_argument('job_name', nargs='?', help='Name of the job to execute')
    parser.add_argument('--add-password', nargs=2, metavar=('PASS_NAME', 'PASS'), 
                       help='Add a password with name PASS_NAME and value PASS')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug logging to console')
    
    args = parser.parse_args()
    
    base_path = args.base_path if args.base_path else None
    
    # Handle --add-password command
    if args.add_password:
        pass_name, password = args.add_password
        executor = JobExecutor(base_path, debug=args.debug)
        if executor.password_manager.add_password(pass_name, password):
            print(f"Password '{pass_name}' added successfully")
            return 0
        else:
            print(f"Failed to add password '{pass_name}'", file=sys.stderr)
            return 1
    
    executor = JobExecutor(base_path, debug=args.debug)
    
    try:
        if args.job_name:
            executor.execute(args.job_name)
        else:
            executor.execute()
    finally:
        executor.close()
    
    return 0


if __name__ == "__main__":
    main()

