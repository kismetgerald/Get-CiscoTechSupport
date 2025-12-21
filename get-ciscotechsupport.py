#!/usr/bin/env python3
#
# ==============================================================================
# Cisco Tech-Support Collector
# ==============================================================================
#
# DESCRIPTION:
#     Automated script for collecting 'show tech-support' output from Cisco
#     IOS/IOS-XE devices. Supports multiple input methods, secure credential
#     management, concurrent connections, and automatic device discovery via
#     SNMP (v2c/v3) or ARP table parsing.
#
# AUTHOR:
#     Kismet Agbasi (Github: kismetgerald Email: KismetG17@gmail.com)
#     
# VERSION:
#     0.0.5
#
# CREATED:
#     December 4, 2025
#
# LAST UPDATED:
#     December 21, 2025
#
# DEPENDENCIES:
#     - Python 3.6+
#     - netmiko: SSH connection handling for network devices
#     - pysnmp: SNMP-based device discovery (v2c and v3)
#     - cryptography (optional): Secure credential storage
#
# INSTALLATION:
#     pip install netmiko pysnmp cryptography
#
# FEATURES:
#     ✓ Multiple device input methods (CLI, file, auto-discovery)
#     ✓ Secure credential management (env vars, encrypted file, interactive)
#     ✓ Cross-platform support (Windows, Linux, macOS)
#     ✓ SNMP v2c and v3 device discovery with ARP fallback
#     ✓ Concurrent device connections for efficiency
#     ✓ Automatic privileged EXEC mode elevation
#     ✓ Comprehensive logging and error handling
#     ✓ Separate offline/failed hosts tracking
#     ✓ Organized output with timestamps and hostnames
#     ✓ Network share support (SMB/CIFS, NFS)
#
# SUPPORTED PLATFORMS:
#     - Cisco IOS
#     - Cisco IOS-XE
#     - Cisco NX-OS (with device_type modification)
#
# USAGE EXAMPLES:
#     
#     NOTE: Use 'py' on Windows or 'python3' on Linux/macOS
#
#     1. Using saved credentials with device list from file:
#        Windows:  py get-ciscotechsupport.py -f devices.txt
#        Linux:    python3 get-ciscotechsupport.py -f devices.txt
#
#     2. Comma-separated device list with environment variables:
#        Windows:  set CISCO_USERNAME=admin & set CISCO_PASSWORD=secret
#                  py get-ciscotechsupport.py -d "10.1.1.1,10.1.1.2,10.1.1.3"
#        Linux:    export CISCO_USERNAME=admin CISCO_PASSWORD=secret
#                  python3 get-ciscotechsupport.py -d "10.1.1.1,10.1.1.2,10.1.1.3"
#
#     3. Auto-discovery via SNMP v2c on subnet:
#        Windows:  py get-ciscotechsupport.py --discover --subnet 192.168.1.0/24
#        Linux:    python3 get-ciscotechsupport.py --discover --subnet 192.168.1.0/24
#
#     4. Auto-discovery via SNMP v3 (authPriv):
#        Windows:  py get-ciscotechsupport.py --discover --subnet 192.168.1.0/24 ^
#                    --snmp-version 3 --snmpv3-user admin ^
#                    --snmpv3-auth-password authpass --snmpv3-priv-password privpass
#        Linux:    python3 get-ciscotechsupport.py --discover --subnet 192.168.1.0/24 \
#                    --snmp-version 3 --snmpv3-user admin \
#                    --snmpv3-auth-password authpass --snmpv3-priv-password privpass
#
#     5. Using specific credentials and custom output directory:
#        Windows:  py get-ciscotechsupport.py -u admin -p mypass -f routers.txt ^
#                    -o Z:\backups\cisco -w 10
#        Linux:    python3 get-ciscotechsupport.py -u admin -p mypass -f routers.txt \
#                    -o /mnt/backups/cisco -w 10
#
#     6. Save credentials securely for future use:
#        Windows:  py get-ciscotechsupport.py --save-credentials
#        Linux:    python3 get-ciscotechsupport.py --save-credentials
#
#     7. Auto-discovery via ARP (no subnet specified):
#        Windows:  py get-ciscotechsupport.py --discover
#        Linux:    python3 get-ciscotechsupport.py --discover
#
# CREDENTIAL SECURITY:
#
#     Priority order for credential retrieval:
#     1. Command-line arguments (-u, -p, -e)
#     2. Environment variables (CISCO_USERNAME, CISCO_PASSWORD, CISCO_ENABLE_SECRET)
#     3. Encrypted credentials file (.cisco_credentials)
#     4. Interactive prompt (secure, no echo)
#
#     Environment Variables:
#         Windows:  set CISCO_USERNAME=admin
#                   set CISCO_PASSWORD=mypassword
#                   set CISCO_ENABLE_SECRET=myenablesecret
#         
#         Linux:    export CISCO_USERNAME=admin
#                   export CISCO_PASSWORD=mypassword
#                   export CISCO_ENABLE_SECRET=myenablesecret
#
#     Encrypted Storage (Recommended for workstations):
#         Windows:  py get-ciscotechsupport.py --save-credentials
#         Linux:    python3 get-ciscotechsupport.py --save-credentials
#         # Credentials encrypted with machine-specific key
#
# OUTPUT FORMAT:
#     Files saved as: {hostname}_{ip}_{timestamp}_tech-support.txt
#     Example: CORE-SW1_10.1.1.1_20241204_143022_tech-support.txt
#
# LOGS:
#     - Logs/collection.log: Main activity log
#     - Logs/hosts_offline.log: Failed/unreachable devices
#
# ERROR HANDLING:
#     - Connection timeouts: Logged and skipped
#     - Authentication failures: Logged and skipped
#     - Unreachable hosts: Logged to offline log
#     - Script continues processing remaining devices
#
# PERFORMANCE:
#     - Default: 5 concurrent connections
#     - Adjustable with -w/--workers parameter
#     - 'show tech-support' timeout: 300 seconds
#
# NOTES:
#     - Requires SSH access to devices
#     - Ensure network connectivity before running
#     - Large networks may take considerable time
#     - Review logs for any failed connections
#     - Compatible with mounted network shares (SMB/CIFS, NFS)
#
# LICENSE:
#     Free to use and modify for network administration purposes
#
# ==============================================================================
#

# region Imports and Configuration

# ============================================================================
# CONFIGURATION SECTION - Modify these variables as needed
# ============================================================================

# Network Discovery Settings
DEFAULT_SNMP_VERSION = '2c'  # '2c' or '3'
DEFAULT_SNMP_COMMUNITY = 'public'  # For SNMPv2c
DEFAULT_SUBNET = None  # e.g., '192.168.1.0/24' or None for ARP-only discovery

# SNMPv3 Settings (only used if DEFAULT_SNMP_VERSION = '3')
DEFAULT_SNMPV3_USER = None
DEFAULT_SNMPV3_AUTH_PROTOCOL = 'SHA'  # 'MD5' or 'SHA'
DEFAULT_SNMPV3_AUTH_PASSWORD = None
DEFAULT_SNMPV3_PRIV_PROTOCOL = 'AES'  # 'DES' or 'AES'
DEFAULT_SNMPV3_PRIV_PASSWORD = None
DEFAULT_SNMPV3_LEVEL = 'authPriv'  # 'noAuthNoPriv', 'authNoPriv', or 'authPriv'

# Connection Settings
DEFAULT_DEVICE_TYPE = 'cisco_ios'
CONNECTION_TIMEOUT = 120
SESSION_TIMEOUT = 120
COMMAND_TIMEOUT = 300  # Timeout for 'show tech-support' command

# Concurrency Settings
DEFAULT_MAX_WORKERS = 5  # Number of simultaneous device connections

# Output Settings
DEFAULT_LOG_FILE = 'collection.log'
DEFAULT_OFFLINE_LOG = 'hosts_offline.log'

# Credential Storage Options
CREDENTIALS_FILE = '.cisco_credentials'  # File to store encrypted credentials
USE_ENV_VARIABLES = True  # Try to read credentials from environment variables first

# File Paths (leave as None for auto-detection based on OS)
DEFAULT_OUTPUT_DIR = None
DEFAULT_DEVICES_FILE = None

# ============================================================================
# END CONFIGURATION SECTION
# ============================================================================

import os
import sys

# Make script self-contained with Python3 subfolder
script_dir = os.path.dirname(os.path.abspath(__file__))
python_root = os.path.join(script_dir, 'Python3')
python_lib = os.path.join(python_root, 'Lib', 'site-packages')
python_scripts = os.path.join(python_root, 'Scripts')

if os.path.exists(python_lib):
    sys.path.insert(0, python_lib)

import argparse
import logging
import os
import sys
import platform
import subprocess
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import ipaddress
import socket
import re
import getpass
import json
from base64 import b64encode, b64decode
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# endregion

# region Library Imports and Availability Checks

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
    NETMIKO_AVAILABLE = True
except ImportError as e:
    NETMIKO_AVAILABLE = False
    NETMIKO_IMPORT_ERROR = str(e)
    # Define placeholder exceptions for when netmiko isn't available
    class NetmikoTimeoutException(Exception):
        pass
    class NetmikoAuthenticationException(Exception):
        pass

# PySNMP version 7.x has a completely different API
try:
    # Try PySNMP v7.x (new API structure)
    from pysnmp import hlapi
    PYSNMP_AVAILABLE = True
    PYSNMP_VERSION = 7
except ImportError:
    try:
        # Try older PySNMP versions (< 7.0) or pysnmp-lextudio
        from pysnmp.hlapi import (
            getCmd,
            SnmpEngine,
            CommunityData,
            UsmUserData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            usmHMACMD5AuthProtocol,
            usmHMACSHAAuthProtocol,
            usmDESPrivProtocol,
            usmAesCfb128Protocol,
            usmNoAuthProtocol,
            usmNoPrivProtocol
        )
        PYSNMP_AVAILABLE = True
        PYSNMP_VERSION = 6
    except ImportError as e:
        PYSNMP_AVAILABLE = False
        PYSNMP_IMPORT_ERROR = str(e)
        PYSNMP_VERSION = None

# Try to import cryptography for secure credential storage
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError as e:
    CRYPTO_AVAILABLE = False
    CRYPTO_IMPORT_ERROR = str(e)

# Try to import jinja2 for email templating
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError as e:
    JINJA2_AVAILABLE = False
    JINJA2_IMPORT_ERROR = str(e)

# Detect OS
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MAC = platform.system() == 'Darwin'

# endregion

# region Credential Manager Class

class CredentialManager:
    """Manage credentials securely using multiple methods"""
    
    def __init__(self, credentials_file=CREDENTIALS_FILE):
        self.credentials_file = credentials_file
        
    def get_credentials(self, username=None, password=None, enable_secret=None, non_interactive=False):
        """
        Get credentials from multiple sources in order of preference:
        1. Provided arguments
        2. Environment variables (if USE_ENV_VARIABLES is True)
        3. Encrypted credentials file
        4. Interactive prompt (only if non_interactive=False)
        """
        creds = {
            'username': username,
            'password': password,
            'enable_secret': enable_secret
        }
        
        # Try environment variables first
        if USE_ENV_VARIABLES:
            if not creds['username']:
                creds['username'] = os.getenv('CISCO_USERNAME')
            if not creds['password']:
                creds['password'] = os.getenv('CISCO_PASSWORD')
            if not creds['enable_secret']:
                creds['enable_secret'] = os.getenv('CISCO_ENABLE_SECRET')
        
        # Try encrypted file
        if not all([creds['username'], creds['password']]):
            file_creds = self.load_credentials()
            if file_creds:
                creds['username'] = creds['username'] or file_creds.get('username')
                creds['password'] = creds['password'] or file_creds.get('password')
                creds['enable_secret'] = creds['enable_secret'] or file_creds.get('enable_secret')
        
        # Check if we're in non-interactive mode (scheduled task) and still missing credentials
        if non_interactive:
            if not creds['username'] or not creds['password']:
                raise ValueError(
                    "Cannot run in non-interactive mode without credentials. "
                    "Provide credentials via: command-line arguments (-u/-p), "
                    "environment variables (CISCO_USERNAME/CISCO_PASSWORD), "
                    "or saved credentials file (run with --save-credentials first)."
                )
            # Set enable secret to password if not provided
            if not creds['enable_secret']:
                creds['enable_secret'] = creds['password']
            return creds
        
        # Interactive prompt for missing credentials (only in interactive mode)
        if not creds['username']:
            creds['username'] = input("Enter username: ")
        
        if not creds['password']:
            creds['password'] = getpass.getpass("Enter password: ")
        
        if not creds['enable_secret']:
            use_same = input("Use same password for enable secret? (Y/n): ").strip().lower()
            if use_same in ['', 'y', 'yes']:
                creds['enable_secret'] = creds['password']
            else:
                creds['enable_secret'] = getpass.getpass("Enter enable secret: ")
        
        return creds
    
    def save_credentials(self, username, password, enable_secret=None):
        """Save credentials to encrypted file"""
        if not CRYPTO_AVAILABLE:
            print("WARNING: cryptography library not installed. Cannot save credentials securely.")
            if 'CRYPTO_IMPORT_ERROR' in globals():
                print(f"Import error details: {CRYPTO_IMPORT_ERROR}")
            print("Install with: pip install cryptography")
            return False
        
        try:
            # Generate a key from a machine-specific identifier
            machine_id = self._get_machine_id()
            key = self._derive_key(machine_id)
            fernet = Fernet(key)
            
            creds = {
                'username': username,
                'password': password,
                'enable_secret': enable_secret or password
            }
            
            # Encrypt and save
            encrypted_data = fernet.encrypt(json.dumps(creds).encode())
            
            with open(self.credentials_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set file permissions (Unix-like systems)
            if not IS_WINDOWS:
                os.chmod(self.credentials_file, 0o600)
            
            print(f"Credentials saved securely to {self.credentials_file}")
            return True
            
        except Exception as e:
            print(f"ERROR saving credentials: {e}")
            return False
    
    def load_credentials(self):
        """Load credentials from encrypted file"""
        if not os.path.exists(self.credentials_file):
            return None
        
        if not CRYPTO_AVAILABLE:
            return None
        
        try:
            machine_id = self._get_machine_id()
            key = self._derive_key(machine_id)
            fernet = Fernet(key)
            
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            creds = json.loads(decrypted_data.decode())
            
            return creds
            
        except Exception as e:
            print(f"WARNING: Could not load saved credentials: {e}")
            return None
    
    def delete_credentials(self):
        """Delete saved credentials file"""
        if os.path.exists(self.credentials_file):
            os.remove(self.credentials_file)
            print(f"Deleted credentials file: {self.credentials_file}")
            return True
        return False
    
    @staticmethod
    def _get_machine_id():
        """Get a machine-specific identifier"""
        if IS_WINDOWS:
            # Use computer name and username
            return f"{os.environ.get('COMPUTERNAME', 'unknown')}_{os.environ.get('USERNAME', 'unknown')}"
        else:
            # Use hostname and username
            import socket
            return f"{socket.gethostname()}_{os.environ.get('USER', 'unknown')}"
    
    @staticmethod
    def _derive_key(password):
        """Derive an encryption key from a password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'cisco_collector_salt_v1',  # Fixed salt for consistency
            iterations=100000,
        )
        key = b64encode(kdf.derive(password.encode()))
        return key

# endregion

# region Helper Functions for Discovery

def get_default_gateway():
    """
    Get the default gateway IP address from the system.
    Works cross-platform (Windows, Linux, macOS)
    """
    try:
        if IS_WINDOWS:
            # Windows: Use 'route print' command
            result = subprocess.run(['route', 'print'], 
                                  capture_output=True, text=True, timeout=5)
            
            # Look for the "Active Routes" section and find default route (0.0.0.0)
            lines = result.stdout.split('\n')
            in_active_routes = False
            
            for line in lines:
                # Find the Active Routes section
                if 'Active Routes' in line:
                    in_active_routes = True
                    continue
                
                # Skip until we're in Active Routes section
                if not in_active_routes:
                    continue
                
                # Stop if we've left the Active Routes section
                if line.strip() == '' or '====' in line:
                    if 'Persistent Routes' in line or 'IPv6' in line:
                        break
                
                # Look for lines with 0.0.0.0 destination (default route)
                # Format: Network Destination    Netmask          Gateway       Interface  Metric
                #         0.0.0.0                0.0.0.0          192.168.1.1   192.168.1.100  35
                parts = line.split()
                
                if len(parts) >= 3 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                    # The gateway is in the 3rd column (index 2)
                    gateway = parts[2]
                    try:
                        ip = ipaddress.ip_address(gateway)
                        # Make sure it's not 0.0.0.0 and is a valid unicast address
                        if not ip.is_unspecified and not ip.is_loopback and not ip.is_multicast:
                            return str(ip)
                    except ValueError:
                        continue
        
        elif IS_LINUX:
            # Linux: Use 'ip route' command
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            # Format: default via 192.168.1.1 dev eth0
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
        
        elif IS_MAC:
            # macOS: Use 'route -n get default' command
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            # Look for 'gateway: x.x.x.x'
            match = re.search(r'gateway:\s*(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    
    except Exception as e:
        pass
    
    return None

def parse_cdp_neighbors(cdp_output):
    """
    Parse 'show cdp neighbors detail' output to extract device information.
    Returns list of dicts with 'hostname', 'ip', and 'platform' keys.
    """
    devices = []
    current_device = {}
    
    lines = cdp_output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Device ID marks start of new neighbor entry
        if line.startswith('Device ID:'):
            if current_device and 'ip' in current_device:
                devices.append(current_device)
            current_device = {}
            device_id = line.split(':', 1)[1].strip()
            # Remove domain suffix if present
            hostname = device_id.split('.')[0]
            current_device['hostname'] = hostname
        
        # IP address - look for various formats
        elif 'IP address:' in line or 'IPv4 Address:' in line:
            # Format: "  IP address: 10.1.1.1" or "Entry address(es): \n  IP address: 10.1.1.1"
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                current_device['ip'] = ip_match.group(1)
        
        elif 'Management address' in line:
            # Some IOS versions use "Management address(es):"
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                current_device['ip'] = ip_match.group(1)
        
        # Platform information
        elif line.startswith('Platform:'):
            platform = line.split(':', 1)[1].strip()
            # Remove capabilities info if present
            platform = platform.split(',')[0].strip()
            current_device['platform'] = platform
    
    # Don't forget the last device
    if current_device and 'ip' in current_device:
        devices.append(current_device)
    
    return devices

# endregion

# region Cisco Collector Class

class CiscoCollector:
    def __init__(self, username, password, enable_secret=None, output_dir=None, 
                 log_file=DEFAULT_LOG_FILE, offline_log=DEFAULT_OFFLINE_LOG,
                 device_type=DEFAULT_DEVICE_TYPE, connection_timeout=CONNECTION_TIMEOUT,
                 session_timeout=SESSION_TIMEOUT, command_timeout=COMMAND_TIMEOUT):
        self.username = username
        self.password = password
        self.enable_secret = enable_secret if enable_secret else password
        self.device_type = device_type
        self.connection_timeout = connection_timeout
        self.session_timeout = session_timeout
        self.command_timeout = command_timeout
        
        # Set default output directory based on OS
        if output_dir is None:
            output_dir = self.get_default_output_dir()
        
        self.output_dir = Path(output_dir)
        
        # Set log file paths to Logs subfolder
        self.log_file = self.get_log_path(log_file)
        self.offline_log = self.get_log_path(offline_log)
        
        # Setup logging
        self.setup_logging()
        
        # Create output directory if it doesn't exist
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Cannot create output directory {self.output_dir}: {e}")
            sys.exit(1)

        # Initialize tracking variables for email notifications
        self.results = []
        self.start_time = None
    
    @staticmethod
    def get_default_output_dir():
        """Get default output directory based on OS"""
        if DEFAULT_OUTPUT_DIR:
            return DEFAULT_OUTPUT_DIR
        
        # Default to 'Results' folder in script directory
        script_dir = Path(__file__).parent.resolve()
        default_results_dir = script_dir / 'Results'
        
        return str(default_results_dir)
    
    @staticmethod
    def get_log_path(log_filename):
        """Get full path for log file in Logs subfolder"""
        script_dir = Path(__file__).parent.resolve()
        logs_dir = script_dir / 'Logs'
        
        # Create Logs directory if it doesn't exist
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        return str(logs_dir / log_filename)
        
    def setup_logging(self):
        """Configure logging for the application"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def log_offline_host(self, host, reason):
        """Log offline/failed hosts to separate file"""
        with open(self.offline_log, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"{timestamp} - {host} - {reason}\n")
    
    # region Device Discovery Methods
    
    # region Device Discovery Methods
    
    def cdp_discover_devices(self, gateway_ip=None, recursive=False, max_depth=2):
        """
        Discover Cisco devices via CDP by querying the default gateway.
        
        Args:
            gateway_ip: IP of gateway to query (auto-detect if None)
            recursive: If True, recursively query discovered neighbors
            max_depth: Maximum recursion depth (default: 2)
        
        Returns:
            List of discovered device IP addresses
        """
        self.logger.info("Starting CDP-based device discovery")
        
        # Get gateway IP
        if not gateway_ip:
            gateway_ip = get_default_gateway()
            if not gateway_ip:
                self.logger.error("Could not determine default gateway")
                return []
            self.logger.info(f"Auto-detected default gateway: {gateway_ip}")
        else:
            self.logger.info(f"Using specified gateway: {gateway_ip}")
        
        # Test if gateway is reachable
        if not self._test_connectivity(gateway_ip):
            self.logger.error(f"Gateway {gateway_ip} is not reachable")
            return []
        
        discovered_ips = set()
        # ADD THE GATEWAY ITSELF TO THE DISCOVERED DEVICES LIST
        discovered_ips.add(gateway_ip)
        self.logger.info(f"Added default gateway to device list: {gateway_ip}")
        
        processed_ips = set()
        to_process = [(gateway_ip, 0)]  # (ip, depth) tuples
        
        while to_process:
            current_ip, depth = to_process.pop(0)
            
            # Skip if already processed
            if current_ip in processed_ips:
                continue
            
            # Skip if max depth reached
            if depth > max_depth:
                continue
            
            processed_ips.add(current_ip)
            self.logger.info(f"Querying CDP on {current_ip} (depth: {depth})")
            
            # Query this device for CDP neighbors
            neighbors = self._query_cdp_neighbors(current_ip)
            
            if neighbors:
                self.logger.info(f"Found {len(neighbors)} CDP neighbor(s) on {current_ip}")
                for neighbor in neighbors:
                    neighbor_ip = neighbor.get('ip')
                    hostname = neighbor.get('hostname', 'unknown')
                    platform = neighbor.get('platform', 'unknown')
                    
                    if neighbor_ip:
                        discovered_ips.add(neighbor_ip)
                        self.logger.info(f"  - {hostname} ({neighbor_ip}) - {platform}")
                        
                        # Add to processing queue if recursive and not already processed
                        if recursive and neighbor_ip not in processed_ips:
                            to_process.append((neighbor_ip, depth + 1))
            else:
                self.logger.warning(f"No CDP neighbors found on {current_ip}")
        
        result = list(discovered_ips)
        self.logger.info(f"CDP discovery complete: found {len(result)} device(s)")
        return result
    
    def _test_connectivity(self, ip, timeout=2):
        """Test if an IP is reachable via ICMP ping"""
        try:
            if IS_WINDOWS:
                result = subprocess.run(['ping', '-n', '1', '-w', str(timeout * 1000), ip],
                                      capture_output=True, timeout=timeout + 1)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), ip],
                                      capture_output=True, timeout=timeout + 1)
            return result.returncode == 0
        except:
            return False
    
    def _query_cdp_neighbors(self, device_ip):
        """
        Connect to a device and retrieve CDP neighbors.
        Returns list of neighbor dicts or empty list on failure.
        """
        device = {
            'device_type': self.device_type,
            'host': device_ip,
            'username': self.username,
            'password': self.password,
            'secret': self.enable_secret,
            'timeout': self.connection_timeout,
            'session_timeout': self.session_timeout,
        }
        
        try:
            # Connect to device
            connection = ConnectHandler(**device)
            
            # Enter enable mode if needed
            if not connection.check_enable_mode():
                connection.enable()
            
            # Check if it's a Cisco device
            version_output = connection.send_command("show version", read_timeout=30)
            if 'cisco' not in version_output.lower():
                self.logger.warning(f"{device_ip}: Not a Cisco device")
                connection.disconnect()
                return []
            
            # Get CDP neighbors detail
            cdp_output = connection.send_command("show cdp neighbors detail", read_timeout=60)
            
            # Check if CDP is enabled
            if 'cdp is not enabled' in cdp_output.lower():
                self.logger.warning(f"{device_ip}: CDP is not enabled")
                connection.disconnect()
                return []
            
            # Parse the output
            neighbors = parse_cdp_neighbors(cdp_output)
            
            connection.disconnect()
            return neighbors
            
        except NetmikoTimeoutException:
            self.logger.error(f"{device_ip}: Connection timeout during CDP query")
            return []
        except NetmikoAuthenticationException:
            self.logger.error(f"{device_ip}: Authentication failed during CDP query")
            return []
        except Exception as e:
            self.logger.error(f"{device_ip}: Error querying CDP: {e}")
            return []

    def snmp_discover_devices(self, subnet, snmp_version='2c', community='public',
                             v3_user=None, v3_auth_protocol='SHA', v3_auth_pass=None,
                             v3_priv_protocol='AES', v3_priv_pass=None, v3_level='authPriv'):
        """Discover Cisco devices using SNMP v2c or v3"""
        self.logger.info(f"Starting SNMP v{snmp_version} discovery on subnet {subnet}")
        devices = []
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            self.logger.error(f"Invalid subnet format: {e}")
            return devices
        
        cisco_oid = '1.3.6.1.2.1.1.1.0'  # sysDescr
        
        # Use different API based on pysnmp version
        if PYSNMP_VERSION == 7:
            # PySNMP v7 API
            for ip in network.hosts():
                ip_str = str(ip)
                try:
                    if snmp_version == '3':
                        if not v3_user:
                            self.logger.error("SNMPv3 requires username")
                            return devices
                        
                        # Build SNMPv3 parameters for v7
                        if v3_level == 'noAuthNoPriv':
                            auth = hlapi.UsmUserData(v3_user)
                        elif v3_level == 'authNoPriv':
                            if not v3_auth_pass:
                                self.logger.error("authNoPriv requires auth password")
                                return devices
                            auth_proto = 'SHA' if v3_auth_protocol.upper() == 'SHA' else 'MD5'
                            auth = hlapi.UsmUserData(v3_user, authKey=v3_auth_pass, authProtocol=auth_proto)
                        else:  # authPriv
                            if not v3_auth_pass or not v3_priv_pass:
                                self.logger.error("authPriv requires both auth and priv passwords")
                                return devices
                            auth_proto = 'SHA' if v3_auth_protocol.upper() == 'SHA' else 'MD5'
                            priv_proto = 'AES' if v3_priv_protocol.upper() == 'AES' else 'DES'
                            auth = hlapi.UsmUserData(
                                v3_user,
                                authKey=v3_auth_pass,
                                privKey=v3_priv_pass,
                                authProtocol=auth_proto,
                                privProtocol=priv_proto
                            )
                    else:
                        # SNMPv2c
                        auth = hlapi.CommunityData(community)
                    
                    # Perform GET operation
                    iterator = hlapi.get(
                        hlapi.SnmpEngine(),
                        auth,
                        hlapi.UdpTransportTarget((ip_str, 161), timeout=1.0, retries=0),
                        hlapi.ContextData(),
                        hlapi.ObjectType(hlapi.ObjectIdentity(cisco_oid))
                    )
                    
                    error_indication, error_status, error_index, var_binds = next(iterator)
                    
                    if error_indication or error_status:
                        continue
                    
                    for var_bind in var_binds:
                        sys_descr = str(var_bind[1]).lower()
                        if 'cisco' in sys_descr or 'ios' in sys_descr:
                            devices.append(ip_str)
                            self.logger.info(f"Found Cisco device via SNMP v{snmp_version}: {ip_str}")
                            break
                
                except Exception as e:
                    continue
        
        else:
            # PySNMP v6 and earlier API
            auth_protocols = {
                'MD5': usmHMACMD5AuthProtocol,
                'SHA': usmHMACSHAAuthProtocol,
                'NONE': usmNoAuthProtocol
            }
            
            priv_protocols = {
                'DES': usmDESPrivProtocol,
                'AES': usmAesCfb128Protocol,
                'NONE': usmNoPrivProtocol
            }
            
            for ip in network.hosts():
                ip_str = str(ip)
                try:
                    if snmp_version == '3':
                        if not v3_user:
                            self.logger.error("SNMPv3 requires username")
                            return devices
                        
                        if v3_level == 'noAuthNoPriv':
                            auth_data = UsmUserData(v3_user)
                        elif v3_level == 'authNoPriv':
                            if not v3_auth_pass:
                                self.logger.error("authNoPriv requires auth password")
                                return devices
                            auth_protocol = auth_protocols.get(v3_auth_protocol.upper(), usmHMACSHAAuthProtocol)
                            auth_data = UsmUserData(
                                v3_user,
                                authKey=v3_auth_pass,
                                authProtocol=auth_protocol
                            )
                        else:  # authPriv
                            if not v3_auth_pass or not v3_priv_pass:
                                self.logger.error("authPriv requires both auth and priv passwords")
                                return devices
                            auth_protocol = auth_protocols.get(v3_auth_protocol.upper(), usmHMACSHAAuthProtocol)
                            priv_protocol = priv_protocols.get(v3_priv_protocol.upper(), usmAesCfb128Protocol)
                            auth_data = UsmUserData(
                                v3_user,
                                authKey=v3_auth_pass,
                                privKey=v3_priv_pass,
                                authProtocol=auth_protocol,
                                privProtocol=priv_protocol
                            )
                    else:
                        # SNMPv2c
                        auth_data = CommunityData(community)
                    
                    iterator = getCmd(
                        SnmpEngine(),
                        auth_data,
                        UdpTransportTarget((ip_str, 161), timeout=1, retries=0),
                        ContextData(),
                        ObjectType(ObjectIdentity(cisco_oid))
                    )
                    
                    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                    
                    if errorIndication or errorStatus:
                        continue
                        
                    for varBind in varBinds:
                        sys_descr = str(varBind[1]).lower()
                        if 'cisco' in sys_descr or 'ios' in sys_descr:
                            devices.append(ip_str)
                            self.logger.info(f"Found Cisco device via SNMP v{snmp_version}: {ip_str}")
                            break
                            
                except Exception as e:
                    continue
        
        self.logger.info(f"SNMP v{snmp_version} discovery found {len(devices)} devices")
        return devices
    
    def arp_discover_devices(self):
        """Fallback: Discover devices from local ARP table (cross-platform)"""
        self.logger.info(f"Starting ARP table discovery on {platform.system()}")
        devices = []
        
        try:
            if IS_LINUX or IS_MAC:
                # Try reading /proc/net/arp on Linux
                if os.path.exists('/proc/net/arp'):
                    with open('/proc/net/arp', 'r') as f:
                        lines = f.readlines()[1:]  # Skip header
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 1:
                                ip = parts[0]
                                try:
                                    ipaddress.ip_address(ip)
                                    devices.append(ip)
                                except ValueError:
                                    continue
                else:
                    # Mac/Unix fallback: use arp -a command
                    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                    # Parse format: hostname (ip) at mac on interface
                    for line in result.stdout.split('\n'):
                        match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                        if match:
                            ip = match.group(1)
                            try:
                                ipaddress.ip_address(ip)
                                devices.append(ip)
                            except ValueError:
                                continue
                                
            elif IS_WINDOWS:
                # Windows: arp -a
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, shell=True)
                # Parse Windows format: IP Address    Physical Address    Type
                for line in result.stdout.split('\n'):
                    # Look for lines with IP addresses
                    match = re.search(r'^\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        try:
                            ipaddress.ip_address(ip)
                            # Skip common non-device IPs
                            if not (ip.endswith('.255') or ip.endswith('.0')):
                                devices.append(ip)
                        except ValueError:
                            continue
                            
        except Exception as e:
            self.logger.error(f"ARP discovery failed: {e}")
            
        self.logger.info(f"ARP discovery found {len(devices)} potential devices")
        return devices
    
    def discover_devices(self, method='cdp', gateway_ip=None, subnet=None, 
                        snmp_version='2c', snmp_community='public',
                        v3_user=None, v3_auth_protocol='SHA', v3_auth_pass=None,
                        v3_priv_protocol='AES', v3_priv_pass=None, v3_level='authPriv'):
        """
        Main discovery function supporting multiple methods.
        
        Args:
            method: Discovery method - 'cdp', 'snmp', 'arp', or 'hybrid'
            gateway_ip: Gateway IP for CDP discovery (auto-detect if None)
            subnet: Subnet for SNMP discovery
            snmp_version: SNMP version ('2c' or '3')
            Other args: SNMP configuration parameters
        
        Returns:
            List of discovered device IPs
        """
        devices = []
        
        if method == 'cdp':
            # CDP discovery from default gateway
            self.logger.info("Using CDP discovery method")
            devices = self.cdp_discover_devices(gateway_ip=gateway_ip, recursive=False)
            
            if not devices:
                self.logger.warning("CDP discovery found no devices")
        
        elif method == 'snmp':
            # SNMP-based subnet scan
            self.logger.info("Using SNMP discovery method")
            if not subnet:
                self.logger.error("SNMP discovery requires --subnet parameter")
                return []
            
            devices = self.snmp_discover_devices(
                subnet, snmp_version, snmp_community,
                v3_user, v3_auth_protocol, v3_auth_pass,
                v3_priv_protocol, v3_priv_pass, v3_level
            )
            
            if not devices:
                self.logger.warning("SNMP discovery found no devices")
        
        elif method == 'arp':
            # ARP table discovery
            self.logger.info("Using ARP discovery method")
            devices = self.arp_discover_devices()
            
            if not devices:
                self.logger.warning("ARP discovery found no devices")
        
        elif method == 'hybrid':
            # Hybrid: CDP + SNMP subnet scan
            self.logger.info("Using hybrid discovery method (CDP + SNMP)")
            
            # Try CDP first
            cdp_devices = self.cdp_discover_devices(gateway_ip=gateway_ip, recursive=False)
            self.logger.info(f"CDP discovered {len(cdp_devices)} device(s)")
            
            # Then SNMP if subnet provided
            snmp_devices = []
            if subnet:
                snmp_devices = self.snmp_discover_devices(
                    subnet, snmp_version, snmp_community,
                    v3_user, v3_auth_protocol, v3_auth_pass,
                    v3_priv_protocol, v3_priv_pass, v3_level
                )
                self.logger.info(f"SNMP discovered {len(snmp_devices)} device(s)")
            else:
                self.logger.warning("No subnet provided for SNMP portion of hybrid discovery")
            
            # Combine results
            devices = list(set(cdp_devices + snmp_devices))
            self.logger.info(f"Hybrid discovery total: {len(devices)} unique device(s)")
        
        else:
            self.logger.error(f"Unknown discovery method: {method}")
            return []
        
        return list(set(devices))  # Remove duplicates
    
    # endregion
    
    # region Device Connection and Collection Methods
    
    def connect_and_collect(self, device_ip):
        """Connect to a device and collect tech-support output"""
        self.logger.info(f"Connecting to {device_ip}")
        
        device = {
            'device_type': self.device_type,
            'host': device_ip,
            'username': self.username,
            'password': self.password,
            'secret': self.enable_secret,
            'timeout': self.connection_timeout,
            'session_timeout': self.session_timeout,
        }
        
        try:
            # Connect to device
            connection = ConnectHandler(**device)
            
            # Enter enable mode if not already there
            if not connection.check_enable_mode():
                self.logger.info(f"{device_ip}: Entering enable mode")
                connection.enable()
            
            self.logger.info(f"{device_ip}: In privileged EXEC mode")
            
            # Get hostname for better file naming
            hostname_output = connection.send_command("show running-config | include hostname")
            hostname = "unknown"
            if hostname_output:
                parts = hostname_output.split()
                if len(parts) >= 2:
                    hostname = parts[1]
            
            # Execute show tech-support (this can take a while)
            self.logger.info(f"{device_ip} ({hostname}): Running 'show tech-support'...")
            output = connection.send_command("show tech-support", read_timeout=self.command_timeout)
            
            # Save output to file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{hostname}_{device_ip}_{timestamp}_tech-support.txt"
            filepath = self.output_dir / filename
            
            with open(filepath, 'w') as f:
                f.write(output)
            
            self.logger.info(f"{device_ip} ({hostname}): Output saved to {filepath}")
            
            # Disconnect
            connection.disconnect()
            
            return {
                'status': 'success',
                'device': device_ip,
                'hostname': hostname,
                'file': str(filepath)
            }
            
        except NetmikoTimeoutException:
            error_msg = f"Connection timeout"
            self.logger.error(f"{device_ip}: {error_msg}")
            self.log_offline_host(device_ip, error_msg)
            return {'status': 'failed', 'device': device_ip, 'error': error_msg}
            
        except NetmikoAuthenticationException:
            error_msg = f"Authentication failed"
            self.logger.error(f"{device_ip}: {error_msg}")
            self.log_offline_host(device_ip, error_msg)
            return {'status': 'failed', 'device': device_ip, 'error': error_msg}
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.logger.error(f"{device_ip}: {error_msg}")
            self.log_offline_host(device_ip, error_msg)
            return {'status': 'failed', 'device': device_ip, 'error': error_msg}
    
    def process_devices(self, devices, max_workers=DEFAULT_MAX_WORKERS):
        """Process multiple devices concurrently"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_device = {
                executor.submit(self.connect_and_collect, device): device 
                for device in devices
            }
            
            for future in as_completed(future_to_device):
                result = future.result()
                results.append(result)
        
        self.results = results  # Store for email notifications
        return results
    
    # endregion

# endregion

# region Helper Functions

def setup_early_logging():
    """Setup logging as early as possible before any operations"""
    script_dir = Path(__file__).parent.resolve()
    logs_dir = script_dir / 'Logs'
    
    # Create Logs directory if it doesn't exist
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = logs_dir / DEFAULT_LOG_FILE
    
    # Configure basic logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

def load_devices_from_file(filepath):
    """Load device list from text file (one IP per line)"""
    devices = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    devices.append(line)
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)
    
    return devices

# endregion

# region Email Notification Functions

def collect_audit_metadata(start_time, end_time):
    """
    Collect comprehensive audit metadata for DoD compliance

    Args:
        start_time: Collection start datetime
        end_time: Collection end datetime

    Returns:
        dict: Audit metadata including timestamps, system info, etc.
    """
    try:
        hostname = socket.gethostname()

        # Get primary IP address
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            host_ip = s.getsockname()[0]
            s.close()
        except:
            host_ip = socket.gethostbyname(hostname)

        # Get domain (Windows-specific, graceful fallback)
        domain = 'N/A'
        if IS_WINDOWS:
            try:
                domain_result = subprocess.run(
                    ['powershell', '-Command', '(Get-WmiObject Win32_ComputerSystem).Domain'],
                    capture_output=True, text=True, timeout=5
                )
                if domain_result.returncode == 0:
                    domain = domain_result.stdout.strip()
            except:
                pass

        # Calculate duration
        duration = end_time - start_time
        hours, remainder = divmod(int(duration.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        metadata = {
            'report_timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            'report_timestamp_long': datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M:%S UTC'),
            'start_timestamp': start_time.strftime('%Y-%m-%d %H:%M:%S UTC') if start_time else 'N/A',
            'end_timestamp': end_time.strftime('%Y-%m-%d %H:%M:%S UTC') if end_time else 'N/A',
            'script_version': '0.0.5',
            'executed_by_user': getpass.getuser(),
            'execution_hostname': hostname,
            'host_ip_address': host_ip,
            'domain': domain,
            'working_directory': os.getcwd(),
            'python_version': platform.python_version(),
            'platform': platform.platform(),
            'duration': duration_str,
        }

        return metadata

    except Exception as e:
        logging.error(f"Failed to collect audit metadata: {e}")
        return {
            'report_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'executed_by_user': 'UNKNOWN',
            'execution_hostname': 'UNKNOWN',
            'host_ip_address': 'UNKNOWN',
            'domain': 'N/A',
            'working_directory': 'N/A',
            'script_version': '0.0.5',
        }


def load_smtp_credentials(cred_file_path):
    """
    Load SMTP credentials from Windows DPAPI encrypted file

    Args:
        cred_file_path: Path to encrypted credential file

    Returns:
        tuple: (username, password) or (None, None) if failed
    """
    if not os.path.exists(cred_file_path):
        logging.warning(f"SMTP credential file not found: {cred_file_path}")
        return None, None

    try:
        if IS_WINDOWS:
            ps_script = f"$cred = Import-Clixml -Path '{cred_file_path}'; $cred.GetNetworkCredential().UserName; $cred.GetNetworkCredential().Password"
            result = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True, text=True, check=True, timeout=10
            )
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                return lines[0].strip(), lines[1].strip()
            else:
                logging.error("SMTP credential file format invalid")
                return None, None
        else:
            logging.warning("SMTP credential file only supported on Windows (DPAPI)")
            return None, None
    except Exception as e:
        logging.error(f"Failed to load SMTP credentials: {e}")
        return None, None


def build_collection_summary(results, start_time, end_time, collection_mode, output_dir):
    """
    Aggregate collection results into summary statistics

    Args:
        results: List of collection result dictionaries
        start_time: Collection start datetime
        end_time: Collection end datetime
        collection_mode: 'DeviceList' or 'Discovery'
        output_dir: Output directory path

    Returns:
        dict: Summary statistics and metadata
    """
    total = len(results)
    successful = sum(1 for r in results if r.get('status') == 'success')
    failed = sum(1 for r in results if r.get('status') == 'failed')
    offline = sum(1 for r in results if r.get('status') == 'offline')

    success_rate = round((successful / total * 100) if total > 0 else 0, 1)

    # Collect top failure reasons
    failure_reasons = {}
    for r in results:
        if r.get('status') in ['failed', 'offline']:
            reason = r.get('error', 'Unknown error')
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

    top_failures = sorted(failure_reasons.items(), key=lambda x: x[1], reverse=True)[:5]
    top_failures = [f"{reason} ({count} devices)" for reason, count in top_failures]

    # Get audit metadata
    metadata = collect_audit_metadata(start_time, end_time)

    summary = {
        'total_devices': total,
        'successful': successful,
        'failed': failed,
        'offline': offline,
        'success_rate': success_rate,
        'collection_mode': collection_mode,
        'output_directory': output_dir,
        'collection_date': datetime.now().strftime('%m/%d/%Y'),
        'top_failures': top_failures,
    }

    # Merge metadata
    summary.update(metadata)

    return summary


def generate_html_email_body(summary):
    """
    Generate HTML email body using Jinja2 template

    Args:
        summary: Summary statistics dictionary

    Returns:
        str: HTML content for email body
    """
    if not JINJA2_AVAILABLE:
        logging.error("Jinja2 not available - cannot generate HTML email")
        return None

    try:
        # Get script directory and template path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        template_dir = os.path.join(script_dir, 'Templates')

        if not os.path.exists(template_dir):
            logging.error(f"Template directory not found: {template_dir}")
            return None

        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

        template = env.get_template('email_template.html')
        html_content = template.render(**summary)

        return html_content

    except Exception as e:
        logging.error(f"Failed to generate HTML email body: {e}")
        return None


def generate_detailed_report_attachment(results, summary):
    """
    Generate detailed HTML report for email attachment

    Args:
        results: List of collection result dictionaries
        summary: Summary statistics dictionary

    Returns:
        tuple: (filename, html_content)
    """
    try:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"cisco-techsupport-report-{timestamp}.html"

        html_parts = []
        html_parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cisco Tech-Support Collection - Detailed Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }

        h1, h2, h3 {
            color: #1e3a8a;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        th {
            background-color: #3b82f6;
            color: white;
            padding: 12px;
            text-align: left;
        }

        td {
            padding: 10px;
            border-bottom: 1px solid #e2e8f0;
        }

        tr:hover {
            background-color: #f8fafc;
        }

        .status-success {
            color: #065f46;
            font-weight: bold;
        }

        .status-failed {
            color: #991b1b;
            font-weight: bold;
        }

        .status-offline {
            color: #92400e;
            font-weight: bold;
        }

        .metadata {
            background-color: white;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <h1>Cisco Tech-Support Collection - Detailed Audit Report</h1>
""")

        # Audit Trail Information
        html_parts.append("<div class='metadata'><h2>AUDIT TRAIL INFORMATION</h2><table>")
        html_parts.append("<tr><th>Attribute</th><th>Value</th></tr>")
        audit_fields = [
            ('Report Generated (UTC)', summary.get('report_timestamp')),
            ('Script Version', summary.get('script_version')),
            ('Executed By (User)', summary.get('executed_by_user')),
            ('Execution Host', summary.get('execution_hostname')),
            ('Host IP Address', summary.get('host_ip_address')),
            ('Domain', summary.get('domain')),
            ('Working Directory', summary.get('working_directory')),
            ('Python Version', summary.get('python_version')),
            ('Platform', summary.get('platform')),
            ('Collection Start', summary.get('start_timestamp')),
            ('Collection End', summary.get('end_timestamp')),
            ('Total Duration', summary.get('duration')),
            ('Collection Mode', summary.get('collection_mode')),
            ('Output Directory', summary.get('output_directory')),
        ]
        for field, value in audit_fields:
            html_parts.append(f"<tr><td>{field}</td><td>{value}</td></tr>")
        html_parts.append("</table></div>")

        # Executive Summary
        html_parts.append("<div class='metadata'><h2>EXECUTIVE SUMMARY</h2><table>")
        html_parts.append("<tr><th>Metric</th><th>Value</th></tr>")
        summary_fields = [
            ('Total Devices', summary.get('total_devices')),
            ('Successful', summary.get('successful')),
            ('Failed', summary.get('failed')),
            ('Offline/Unreachable', summary.get('offline')),
            ('Success Rate', f"{summary.get('success_rate')}%"),
        ]
        for field, value in summary_fields:
            html_parts.append(f"<tr><td>{field}</td><td>{value}</td></tr>")
        html_parts.append("</table></div>")

        # Device Details
        html_parts.append("<h2>DEVICE-BY-DEVICE RESULTS</h2><table>")
        html_parts.append("<tr><th>Device IP</th><th>Hostname</th><th>Status</th><th>Details</th></tr>")

        for result in results:
            device = result.get('device', 'Unknown')
            hostname = result.get('hostname', 'N/A')
            status = result.get('status', 'unknown')

            status_class = 'status-success' if status == 'success' else ('status-offline' if status == 'offline' else 'status-failed')
            status_text = status.upper()

            details = result.get('file_path', '') if status == 'success' else result.get('error', 'No details')

            html_parts.append(f"<tr>")
            html_parts.append(f"  <td>{device}</td>")
            html_parts.append(f"  <td>{hostname}</td>")
            html_parts.append(f"  <td class='{status_class}'>{status_text}</td>")
            html_parts.append(f"  <td>{details}</td>")
            html_parts.append(f"</tr>")

        html_parts.append("</table>")
        html_parts.append("</body></html>")

        html_content = '\n'.join(html_parts)

        return filename, html_content

    except Exception as e:
        logging.error(f"Failed to generate detailed report: {e}")
        return None, None


def send_email_notification(smtp_config, summary, results):
    """
    Send email notification with HTML summary and detailed attachment

    Args:
        smtp_config: Dict with SMTP configuration
        summary: Summary statistics dictionary
        results: List of collection result dictionaries

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        # Validate required config
        if not smtp_config.get('server'):
            logging.error("SMTP server not specified")
            return False
        if not smtp_config.get('from'):
            logging.error("Email 'from' address not specified")
            return False
        if not smtp_config.get('to'):
            logging.error("Email 'to' addresses not specified")
            return False

        # Prepare email subject
        subject = smtp_config.get('subject')
        if not subject:
            subject = f"Cisco Tech-Support Collection Report - {summary.get('collection_date')}"
        elif not any(char.isdigit() for char in subject):
            # Append date if not already present
            subject = f"{subject} - {summary.get('collection_date')}"

        # Create message
        msg = MIMEMultipart('mixed')
        msg['Subject'] = subject
        msg['From'] = smtp_config['from']
        msg['To'] = ', '.join(smtp_config['to'])

        # Generate HTML body
        html_body = generate_html_email_body(summary)
        if html_body:
            msg.attach(MIMEText(html_body, 'html'))
        else:
            # Fallback to plain text if HTML generation fails
            text_body = f"""
Cisco Tech-Support Collection Report
{'='*50}

Total Devices: {summary.get('total_devices')}
Successful: {summary.get('successful')}
Failed: {summary.get('failed')}
Offline: {summary.get('offline')}
Success Rate: {summary.get('success_rate')}%

Collection completed on {summary.get('collection_date')}

See attached detailed report for device-by-device breakdown.
"""
            msg.attach(MIMEText(text_body, 'plain'))

        # Generate and attach detailed report
        filename, detailed_html = generate_detailed_report_attachment(results, summary)
        if filename and detailed_html:
            attachment = MIMEBase('text', 'html')
            attachment.set_payload(detailed_html.encode('utf-8'))
            encoders.encode_base64(attachment)
            attachment.add_header('Content-Disposition', f'attachment; filename="{filename}"')
            msg.attach(attachment)

        # Send email via SMTP
        logging.info(f"Connecting to SMTP server: {smtp_config['server']}:{smtp_config.get('port', 25)}")

        if smtp_config.get('use_ssl'):
            server = smtplib.SMTP_SSL(smtp_config['server'], smtp_config.get('port', 465), timeout=30)
        else:
            server = smtplib.SMTP(smtp_config['server'], smtp_config.get('port', 25), timeout=30)
            if smtp_config.get('use_starttls'):
                server.starttls()

        # Authenticate if credentials provided
        if smtp_config.get('username') and smtp_config.get('password'):
            logging.info("Authenticating to SMTP server...")
            server.login(smtp_config['username'], smtp_config['password'])

        # Send email
        logging.info(f"Sending email to: {', '.join(smtp_config['to'])}")
        server.send_message(msg)
        server.quit()

        logging.info("Email notification sent successfully")
        return True

    except Exception as e:
        logging.error(f"Failed to send email notification: {e}")
        return False

# endregion

# region Main Function

def main():
    # Setup logging FIRST - before any other operations
    early_logger = setup_early_logging()
    early_logger.info("="*60)
    early_logger.info("Cisco Tech-Support Collector Starting")
    early_logger.info("="*60)
    
    parser = argparse.ArgumentParser(
        description='Collect tech-support from Cisco devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Comma-separated list
  %(prog)s -u admin -p password -d "192.168.1.1,192.168.1.2,192.168.1.3"
  
  # From file
  %(prog)s -u admin -f devices.txt
  
  # Auto-discovery via SNMP v2c
  %(prog)s --discover --subnet 192.168.1.0/24
  
  # Auto-discovery via SNMP v3
  %(prog)s --discover --subnet 192.168.1.0/24 --snmp-version 3 \
    --snmpv3-user admin --snmpv3-auth-password authpass \
    --snmpv3-priv-password privpass
  
  # Use environment variables for credentials
  export CISCO_USERNAME=admin
  export CISCO_PASSWORD=secret123
  %(prog)s -f devices.txt
  
  # Save credentials securely
  %(prog)s --save-credentials
  
  # Use saved credentials
  %(prog)s -f devices.txt
  
  # Override default timeouts
  %(prog)s -f devices.txt --connection-timeout 180 --command-timeout 600
  
  # Change device type for NX-OS
  %(prog)s -f nexus_switches.txt --device-type cisco_nxos
        """
    )
    
    # Authentication
    parser.add_argument('-u', '--username', help='Device username')
    parser.add_argument('-p', '--password', help='Device password (not recommended, use env vars or saved creds)')
    parser.add_argument('-e', '--enable', help='Enable secret')
    parser.add_argument('--save-credentials', action='store_true', 
                       help='Save credentials securely for future use')
    parser.add_argument('--delete-credentials', action='store_true',
                       help='Delete saved credentials')
    parser.add_argument('--credentials-file', default=CREDENTIALS_FILE,
                       help=f'Path to credentials file (default: {CREDENTIALS_FILE})')
    
    # Device input methods
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-d', '--devices', help='Comma-separated list of device IPs')
    input_group.add_argument('-f', '--file', help='Text file with device IPs (one per line)')
    input_group.add_argument('--discover', action='store_true', help='Auto-discover devices')
    
    # Discovery options
    parser.add_argument('--method', choices=['cdp', 'snmp', 'arp', 'hybrid'],
                       default='cdp',
                       help='Discovery method: cdp (default, uses gateway CDP), snmp (subnet scan), '
                            'arp (local ARP table), hybrid (cdp + snmp)')
    parser.add_argument('--gateway', help='Gateway IP for CDP discovery (auto-detect if not specified)')
    parser.add_argument('--subnet', help='Subnet for SNMP discovery (e.g., 192.168.1.0/24)')
    parser.add_argument('--snmp-version', choices=['2c', '3'], default=DEFAULT_SNMP_VERSION,
                       help=f'SNMP version (default: {DEFAULT_SNMP_VERSION})')
    parser.add_argument('--snmp-community', default=DEFAULT_SNMP_COMMUNITY, 
                       help=f'SNMPv2c community string (default: {DEFAULT_SNMP_COMMUNITY})')
    
    # SNMPv3 options
    parser.add_argument('--snmpv3-user', help='SNMPv3 username')
    parser.add_argument('--snmpv3-level', choices=['noAuthNoPriv', 'authNoPriv', 'authPriv'],
                       default=DEFAULT_SNMPV3_LEVEL,
                       help=f'SNMPv3 security level (default: {DEFAULT_SNMPV3_LEVEL})')
    parser.add_argument('--snmpv3-auth-protocol', choices=['MD5', 'SHA'],
                       default=DEFAULT_SNMPV3_AUTH_PROTOCOL,
                       help=f'SNMPv3 auth protocol (default: {DEFAULT_SNMPV3_AUTH_PROTOCOL})')
    parser.add_argument('--snmpv3-auth-password', help='SNMPv3 authentication password')
    parser.add_argument('--snmpv3-priv-protocol', choices=['DES', 'AES'],
                       default=DEFAULT_SNMPV3_PRIV_PROTOCOL,
                       help=f'SNMPv3 privacy protocol (default: {DEFAULT_SNMPV3_PRIV_PROTOCOL})')
    parser.add_argument('--snmpv3-priv-password', help='SNMPv3 privacy password')
    
    # Connection settings
    parser.add_argument('--device-type', default=DEFAULT_DEVICE_TYPE,
                       help=f'Device type for Netmiko (default: {DEFAULT_DEVICE_TYPE})')
    parser.add_argument('--connection-timeout', type=int, default=CONNECTION_TIMEOUT,
                       help=f'Connection timeout in seconds (default: {CONNECTION_TIMEOUT})')
    parser.add_argument('--session-timeout', type=int, default=SESSION_TIMEOUT,
                       help=f'Session timeout in seconds (default: {SESSION_TIMEOUT})')
    parser.add_argument('--command-timeout', type=int, default=COMMAND_TIMEOUT,
                       help=f'Command timeout in seconds (default: {COMMAND_TIMEOUT})')
    
    # Output options
    parser.add_argument('-o', '--output-dir',
                       help=f'Output directory for tech-support files '
                            f'(default: auto-detected based on OS)')
    parser.add_argument('--log-file', default=DEFAULT_LOG_FILE, help='Main log file')
    parser.add_argument('--offline-log', default=DEFAULT_OFFLINE_LOG, help='Offline hosts log file')
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_MAX_WORKERS,
                       help=f'Number of concurrent connections (default: {DEFAULT_MAX_WORKERS})')
    parser.add_argument('--non-interactive', action='store_true',
                       help='Run in non-interactive mode (for scheduled tasks) - will fail if credentials not available')

    # Email notification options
    email_group = parser.add_argument_group('Email Notification Options')
    email_group.add_argument('--send-email', action='store_true',
                            help='Send email notification after collection completes')
    email_group.add_argument('--smtp-server', type=str,
                            help='SMTP server hostname or IP address')
    email_group.add_argument('--smtp-port', type=int, default=25,
                            help='SMTP server port (default: 25)')
    email_group.add_argument('--smtp-use-ssl', action='store_true',
                            help='Use SSL/TLS for SMTP connection (port 465)')
    email_group.add_argument('--smtp-use-starttls', action='store_true',
                            help='Use STARTTLS for SMTP connection (port 587)')
    email_group.add_argument('--email-from', type=str,
                            help='Sender email address')
    email_group.add_argument('--email-to', type=str,
                            help='Recipient email addresses (comma-separated)')
    email_group.add_argument('--email-subject', type=str,
                            help='Email subject line (default: auto-generated with date)')
    email_group.add_argument('--smtp-cred-file', type=str,
                            help='Path to SMTP credential file (encrypted, Windows DPAPI)')
    email_group.add_argument('--smtp-username', type=str,
                            help='SMTP username for authentication')
    email_group.add_argument('--smtp-password', type=str,
                            help='SMTP password for authentication')

    args = parser.parse_args()
    
    early_logger.info(f"Running in {'non-interactive' if args.non_interactive else 'interactive'} mode")
    
    # Handle credential management (doesn't require netmiko/pysnmp)
    cred_manager = CredentialManager(credentials_file=args.credentials_file)
    
    if args.delete_credentials:
        early_logger.info("Deleting saved credentials")
        cred_manager.delete_credentials()
        return
    
    if args.save_credentials:
        early_logger.info("Saving credentials")
        print("Save Credentials")
        print("=" * 50)
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        use_same = input("Use same password for enable secret? (Y/n): ").strip().lower()
        if use_same in ['', 'y', 'yes']:
            enable_secret = password
        else:
            enable_secret = getpass.getpass("Enter enable secret: ")
        
        cred_manager.save_credentials(username, password, enable_secret)
        return
    
    # Check for required libraries for device operations
    if not NETMIKO_AVAILABLE or not PYSNMP_AVAILABLE:
        error_msg = "ERROR: Required libraries not installed for device operations."
        early_logger.error(error_msg)
        print(error_msg)
        missing = []
        if not NETMIKO_AVAILABLE:
            missing.append("netmiko")
            if 'NETMIKO_IMPORT_ERROR' in globals():
                early_logger.error(f"Netmiko import error: {NETMIKO_IMPORT_ERROR}")
                print(f"Netmiko import error: {NETMIKO_IMPORT_ERROR}")
        if not PYSNMP_AVAILABLE:
            missing.append("pysnmp")
            if 'PYSNMP_IMPORT_ERROR' in globals():
                early_logger.error(f"PySNMP import error: {PYSNMP_IMPORT_ERROR}")
                print(f"PySNMP import error: {PYSNMP_IMPORT_ERROR}")
        print(f"Please run: pip install {' '.join(missing)}")
        sys.exit(1)
    
    # Get credentials with non-interactive flag
    try:
        creds = cred_manager.get_credentials(
            args.username, 
            args.password, 
            args.enable, 
            non_interactive=args.non_interactive
        )
        early_logger.info(f"Credentials obtained for user: {creds['username']}")
    except ValueError as e:
        early_logger.error(f"Credential error: {e}")
        print(f"ERROR: {e}")
        sys.exit(1)
    except Exception as e:
        early_logger.error(f"Unexpected error getting credentials: {e}")
        print(f"ERROR: {e}")
        sys.exit(1)
    
    # Require at least one input method
    if not any([args.devices, args.file, args.discover]):
        error_msg = "Must specify one of: --devices, --file, or --discover"
        early_logger.error(error_msg)
        parser.error(error_msg)
    
    # Show OS detection info
    os_info = f"{platform.system()} {platform.release()}"
    early_logger.info(f"Detected OS: {os_info}")
    print(f"Detected OS: {os_info}")
    
    # Initialize collector with custom settings
    collector = CiscoCollector(
        username=creds['username'],
        password=creds['password'],
        enable_secret=creds['enable_secret'],
        output_dir=args.output_dir,
        log_file=args.log_file,
        offline_log=args.offline_log,
        device_type=args.device_type,
        connection_timeout=args.connection_timeout,
        session_timeout=args.session_timeout,
        command_timeout=args.command_timeout
    )

    # Capture start time for email reporting
    collector.start_time = datetime.now(timezone.utc)
    
    print(f"Output directory: {collector.output_dir}")
    print(f"Log directory: {Path(collector.log_file).parent}")
    print(f"Device type: {collector.device_type}")
    print(f"Connection timeout: {collector.connection_timeout}s")
    print(f"Command timeout: {collector.command_timeout}s")
    print()
    
    # Determine device list
    devices = []
    
    if args.devices:
        devices = [d.strip() for d in args.devices.split(',')]
    elif args.file:
        devices = load_devices_from_file(args.file)
    elif args.discover:
        devices = collector.discover_devices(
            method=args.method,
            gateway_ip=args.gateway,
            subnet=args.subnet,
            snmp_version=args.snmp_version,
            snmp_community=args.snmp_community,
            v3_user=args.snmpv3_user,
            v3_auth_protocol=args.snmpv3_auth_protocol,
            v3_auth_pass=args.snmpv3_auth_password,
            v3_priv_protocol=args.snmpv3_priv_protocol,
            v3_priv_pass=args.snmpv3_priv_password,
            v3_level=args.snmpv3_level
        )
        if not devices:
            collector.logger.error("No devices discovered")
            sys.exit(1)
    
    collector.logger.info(f"Processing {len(devices)} device(s)")
    
    # Process all devices
    results = collector.process_devices(devices, max_workers=args.workers)
    
    # Summary
    successful = sum(1 for r in results if r['status'] == 'success')
    failed = sum(1 for r in results if r['status'] == 'failed')
    
    # Log summary to file
    collector.logger.info("="*60)
    collector.logger.info("COLLECTION SUMMARY")
    collector.logger.info("="*60)
    collector.logger.info(f"Total devices: {len(devices)}")
    collector.logger.info(f"Successful: {successful}")
    collector.logger.info(f"Failed: {failed}")
    collector.logger.info(f"Output directory: {collector.output_dir}")
    collector.logger.info(f"Main log: {collector.log_file}")
    collector.logger.info(f"Offline hosts log: {collector.offline_log}")
    collector.logger.info("="*60)
    collector.logger.info("Cisco Tech-Support Collector COMPLETED SUCCESSFULLY")
    collector.logger.info("="*60)

   # Print summary to console
    print("\n" + "="*60)
    print("COLLECTION SUMMARY")
    print("="*60)
    print(f"Total devices: {len(devices)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"\nOutput directory: {collector.output_dir}")
    print(f"Main log: {collector.log_file}")
    print(f"Offline hosts log: {collector.offline_log}")
    print("="*60)

    # Send email notification if configured
    if args.send_email:
        try:
            collector.logger.info("Sending email notification...")
            print("\nSending email notification...")

            # Load SMTP credentials if credential file specified
            smtp_username, smtp_password = None, None
            if args.smtp_cred_file:
                smtp_username, smtp_password = load_smtp_credentials(args.smtp_cred_file)

            # Build SMTP configuration
            smtp_config = {
                'server': args.smtp_server,
                'port': args.smtp_port,
                'use_ssl': args.smtp_use_ssl,
                'use_starttls': args.smtp_use_starttls,
                'from': args.email_from,
                'to': args.email_to.split(',') if args.email_to else [],
                'subject': args.email_subject,
                'username': smtp_username or args.smtp_username,
                'password': smtp_password or args.smtp_password,
            }

            # Determine collection mode
            collection_mode = 'Discovery' if args.discover else 'DeviceList'

            # Build summary with results
            summary = build_collection_summary(
                collector.results,
                collector.start_time,
                datetime.now(timezone.utc),
                collection_mode,
                collector.output_dir
            )

            # Send email notification
            email_sent = send_email_notification(smtp_config, summary, collector.results)

            if email_sent:
                collector.logger.info("Email notification sent successfully")
                print("Email notification sent successfully")
            else:
                collector.logger.warning("Email notification failed (see log for details)")
                print("Warning: Email notification failed (see log for details)")

        except Exception as e:
            collector.logger.error(f"Email notification failed: {e}")
            print(f"Warning: Email notification failed: {e}")
            # Don't fail entire script if email fails

# endregion

# region Script Entry Point

if __name__ == '__main__':
    main()

# endregion