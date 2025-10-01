# Proxmox SPICE Launch

A simple Go application that connects to the Proxmox SPICE API, retrieves connection details, and launches a SPICE client to connect to a virtual machine.

## Features

- Connect to Proxmox VE API
- Authenticate using username/password OR API tokens
- Retrieve SPICE connection details for a specific VM
- Launch SPICE client with the connection details
- Configurable via YAML file, command line arguments, or environment variables
- Comprehensive command line flag support with short and long options

## Configuration

The application can be configured in three ways (in order of precedence):

1. Command line arguments (highest priority)
2. Environment variables
3. YAML configuration file (lowest priority)

### Command Line Arguments

All options support both long and short forms:

- `--host`, `-h` - Proxmox server hostname or IP
- `--port`, `-p` - Proxmox web interface port (default: 8006)
- `--username`, `-u` - Proxmox username
- `--password`, `-w` - Proxmox password
- `--node`, `-n` - Proxmox node name
- `--vmid`, `-v` - VM ID to connect to
- `--realm`, `-r` - Authentication realm (default: pam)
- `--api-token`, `-t` - API token (USER@REALM!TOKENID=UUID)
- `--client-path`, `-cp` - Path to SPICE client executable
- `--config` - Path to configuration file (default: config.yaml)

### Environment Variables

All environment variables start with `PROXMOX_SPICE_`:

- `PROXMOX_SPICE_HOST` - Proxmox server hostname or IP
- `PROXMOX_SPICE_PORT` - Proxmox web interface port (default: 8006)
- `PROXMOX_SPICE_USERNAME` - Proxmox username
- `PROXMOX_SPICE_PASSWORD` - Proxmox password
- `PROXMOX_SPICE_NODE` - Proxmox node name
- `PROXMOX_SPICE_VMID` - VM ID to connect to
- `PROXMOX_SPICE_REALM` - Authentication realm (default: pam)
- `PROXMOX_SPICE_API_TOKEN` - API token (USER@REALM!TOKENID=UUID)
- `PROXMOX_SPICE_CLIENT_PATH` - Path to SPICE client executable

### YAML Configuration

Copy `config.yaml` and modify the values:

```yaml
proxmox:
  host: "your-proxmox-host.com"
  port: 8006
  username: "your-username"         # Optional if using API token
  password: "your-password"         # Optional if using API token
  node: "your-node-name"
  vmid: 100
  realm: "pam"
  api_token: ""                     # API token (alternative to username/password)

spice:
  client_path: "remote-viewer.exe"
```

## Authentication Methods

### Username/Password Authentication
The traditional method using username and password:

```yaml
proxmox:
  username: "root"
  password: "your-password"
  realm: "pam"
```

### API Token Authentication
More secure method using API tokens. Create an API token in Proxmox web interface under Datacenter > Permissions > API Tokens:

```yaml
proxmox:
  api_token: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

## Building

```bash
go mod tidy
go build -o proxmox-spice-launch.exe
```

## Usage

### Using default config file
```bash
./proxmox-spice-launch
```

### Using command line arguments
```bash
./proxmox-spice-launch --host 192.168.1.100 --username root --password mypass --node pve --vmid 100
```

### Using short flags
```bash
./proxmox-spice-launch -h 192.168.1.100 -u root -w mypass -n pve -v 100
```

### Using API token
```bash
./proxmox-spice-launch --host 192.168.1.100 --api-token "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" --node pve --vmid 100
```

### Using environment variables
```bash
set PROXMOX_SPICE_HOST=192.168.1.100
set PROXMOX_SPICE_API_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
set PROXMOX_SPICE_NODE=pve
set PROXMOX_SPICE_VMID=100
./proxmox-spice-launch
```

## Requirements

- Go 1.21 or later
- SPICE client (remote-viewer) installed on your system
  - Windows: Download from [virt-viewer releases](https://github.com/virt-manager/virt-viewer/releases)
  - Linux: `sudo apt install virt-viewer` or `sudo yum install virt-viewer`
  - macOS: Install via homebrew `brew install virt-viewer`

## SPICE Client Installation

### Windows
1. Download the virt-viewer MSI installer from the official releases
2. Install to the default location or update the `client_path` in your configuration

### Linux
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install virt-viewer

# CentOS/RHEL/Fedora
sudo yum install virt-viewer
# or
sudo dnf install virt-viewer
```

### macOS
```bash
brew install virt-viewer
```

## Security Notes

- The application disables TLS certificate verification for Proxmox connections (common in lab environments)
- Store sensitive configuration like passwords in environment variables rather than config files
- Ensure your SPICE client is up to date for security