package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Proxmox ProxmoxConfig `yaml:"proxmox"`
	SPICE   SPICEConfig   `yaml:"spice"`
}

// ProxmoxConfig contains Proxmox connection settings
type ProxmoxConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Node     string `yaml:"node"`
	VMID     int    `yaml:"vmid"`
	Realm    string `yaml:"realm"`
	// API Token authentication (alternative to username/password)
	TokenID  string `yaml:"tokenId"`   // Format
	APIToken string `yaml:"api_token"` // Format: USER@REALM!TOKENID=UUID

}

// SPICEConfig contains SPICE client settings
type SPICEConfig struct {
	ClientPath string `yaml:"client_path"`
}

// SPICEResponse represents the API response from Proxmox SPICE proxy
type SPICEResponse struct {
	Data struct {
		Host        string `json:"host"`
		Password    string `json:"password"`
		Proxy       string `json:"proxy"`
		TLSPort     int    `json:"tls-port"`
		Type        string `json:"type"`
		Title       string `json:"title"`
		CA          string `json:"ca"`
		HostSubject string `json:"host-subject"`
	} `json:"data"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	Data struct {
		Ticket    string `json:"ticket"`
		CSRFToken string `json:"CSRFPreventionToken"`
	} `json:"data"`
}

func main() {

	// Parse command line flags
	var configFile string
	var host, username, password, node, realm, apiToken, clientPath string
	var port, vmid int

	flag.StringVar(&configFile, "config", "config.yaml", "Path to configuration file")
	flag.StringVar(&configFile, "c", "config.yaml", "Alias for --config")
	flag.StringVar(&host, "host", "", "Proxmox server hostname or IP")
	flag.StringVar(&host, "h", "", "Alias for --host")
	flag.IntVar(&port, "port", 0, "Proxmox web interface port")
	flag.IntVar(&port, "p", 0, "Alias for --port")
	flag.StringVar(&username, "username", "", "Proxmox username")
	flag.StringVar(&username, "u", "", "Alias for --username")
	flag.StringVar(&password, "password", "", "Proxmox password")
	flag.StringVar(&password, "w", "", "Alias for --password")
	flag.StringVar(&node, "node", "", "Proxmox node name")
	flag.StringVar(&node, "n", "", "Alias for --node")
	flag.IntVar(&vmid, "vmid", 0, "VM ID to connect to")
	flag.IntVar(&vmid, "v", 0, "Alias for --vmid")
	flag.StringVar(&realm, "realm", "", "Authentication realm")
	flag.StringVar(&realm, "r", "", "Alias for --realm")
	flag.StringVar(&apiToken, "api-token", "", "API token (USER@REALM!TOKENID=UUID)")
	flag.StringVar(&apiToken, "t", "", "Alias for --api-token")
	flag.StringVar(&clientPath, "client-path", "", "Path to SPICE client executable")
	flag.StringVar(&clientPath, "cp", "", "Alias for --client-path")

	flag.Parse()

	// Load configuration
	config, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Override with environment variables
	overrideWithEnv(config)

	// Override with command line flags
	overrideWithFlags(config, host, port, username, password, node, vmid, realm, apiToken, clientPath)

	// Validate required configuration
	if err := validateConfig(config); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	var ticket, csrfToken string

	// Choose authentication method
	if config.Proxmox.APIToken != "" {
		fmt.Println("Using API token authentication")
	} else {
		fmt.Println("Using username/password authentication")
		// Authenticate with Proxmox
		ticket, csrfToken, err = authenticate(config.Proxmox)
		if err != nil {
			log.Fatalf("Authentication failed: %v", err)
		}
	}

	// Get SPICE connection details
	spiceDetails, err := getSPICEDetails(config.Proxmox, ticket, csrfToken)
	if err != nil {
		log.Fatalf("Failed to get SPICE details: %v", err)
	}

	// Launch SPICE client
	err = launchSPICEClient(config.SPICE, spiceDetails)
	if err != nil {
		log.Fatalf("Failed to launch SPICE client: %v", err)
	}

	fmt.Println("SPICE client launched successfully")
}

func loadConfig(filename string) (*Config, error) {
	// Default configuration
	config := &Config{
		Proxmox: ProxmoxConfig{
			Port:  8006,
			Realm: "pam",
		},
		SPICE: SPICEConfig{
			ClientPath: getDefaultSPICEClient(),
		},
	}

	// Try to read config file
	if _, err := os.Stat(filename); err == nil {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	return config, nil
}

func overrideWithFlags(config *Config, host string, port int, username, password, node string, vmid int, realm, apiToken, clientPath string) {
	if host != "" {
		config.Proxmox.Host = host
	}
	if port != 0 {
		config.Proxmox.Port = port
	}
	if username != "" {
		config.Proxmox.Username = username
	}
	if password != "" {
		config.Proxmox.Password = password
	}
	if node != "" {
		config.Proxmox.Node = node
	}
	if vmid != 0 {
		config.Proxmox.VMID = vmid
	}
	if realm != "" {
		config.Proxmox.Realm = realm
	}
	if apiToken != "" {
		config.Proxmox.APIToken = apiToken
	}
	if clientPath != "" {
		config.SPICE.ClientPath = clientPath
	}
}

func overrideWithEnv(config *Config) {
	if val := os.Getenv("PROXMOX_SPICE_HOST"); val != "" {
		config.Proxmox.Host = val
	}
	if val := os.Getenv("PROXMOX_SPICE_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			config.Proxmox.Port = port
		}
	}
	if val := os.Getenv("PROXMOX_SPICE_USERNAME"); val != "" {
		config.Proxmox.Username = val
	}
	if val := os.Getenv("PROXMOX_SPICE_PASSWORD"); val != "" {
		config.Proxmox.Password = val
	}
	if val := os.Getenv("PROXMOX_SPICE_NODE"); val != "" {
		config.Proxmox.Node = val
	}
	if val := os.Getenv("PROXMOX_SPICE_VMID"); val != "" {
		if vmid, err := strconv.Atoi(val); err == nil {
			config.Proxmox.VMID = vmid
		}
	}
	if val := os.Getenv("PROXMOX_SPICE_REALM"); val != "" {
		config.Proxmox.Realm = val
	}
	if val := os.Getenv("PROXMOX_SPICE_API_TOKEN"); val != "" {
		config.Proxmox.APIToken = val
	}
	if val := os.Getenv("PROXMOX_SPICE_CLIENT_PATH"); val != "" {
		config.SPICE.ClientPath = val
	}
}

func validateConfig(config *Config) error {
	if config.Proxmox.Host == "" {
		return fmt.Errorf("proxmox host is required")
	}
	if config.Proxmox.Node == "" {
		return fmt.Errorf("proxmox node is required")
	}
	if config.Proxmox.VMID == 0 {
		return fmt.Errorf("proxmox vmid is required")
	}
	if config.SPICE.ClientPath == "" {
		return fmt.Errorf("spice client path is required")
	}

	// Check authentication method
	if config.Proxmox.APIToken == "" {
		// Username/password authentication
		if config.Proxmox.Username == "" {
			return fmt.Errorf("proxmox username is required (or use API token)")
		}
		if config.Proxmox.Password == "" {
			return fmt.Errorf("proxmox password is required (or use API token)")
		}
	}

	return nil
}

func authenticate(config ProxmoxConfig) (string, string, error) {
	// Create HTTP client with TLS verification disabled (common for Proxmox)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Prepare authentication data
	authURL := fmt.Sprintf("https://%s:%d/api2/json/access/ticket", config.Host, config.Port)
	data := url.Values{}
	data.Set("username", fmt.Sprintf("%s@%s", config.Username, config.Realm))
	data.Set("password", config.Password)

	// Make authentication request
	resp, err := client.PostForm(authURL, data)
	if err != nil {
		return "", "", fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read authentication response: %w", err)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", "", fmt.Errorf("failed to parse authentication response: %w", err)
	}

	return authResp.Data.Ticket, authResp.Data.CSRFToken, nil
}

func getSPICEDetails(config ProxmoxConfig, ticket, csrfToken string) (*SPICEResponse, error) {
	// Create HTTP client with TLS verification disabled
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Prepare SPICE proxy request
	spiceURL := fmt.Sprintf("https://%s:%d/api2/json/nodes/%s/qemu/%d/spiceproxy?proxy=%s",
		config.Host, config.Port, config.Node, config.VMID, config.Host)

	req, err := http.NewRequest("POST", spiceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPICE request: %w", err)
	}

	// Add authentication headers based on method
	if config.APIToken != "" {
		// API Token authentication
		//PVEAPIToken=root@pam!spice={{TOKEN}}
		req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s@%s!%s=%s", config.Username, config.Realm, config.TokenID, config.APIToken))
	} else {
		// Cookie authentication
		req.Header.Set("Cookie", fmt.Sprintf("PVEAuthCookie=%s", ticket))
		req.Header.Set("CSRFPreventionToken", csrfToken)
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SPICE request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SPICE request failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read SPICE response: %w", err)
	}

	var spiceResp SPICEResponse
	if err := json.Unmarshal(body, &spiceResp); err != nil {
		return nil, fmt.Errorf("failed to parse SPICE response: %w", err)
	}

	return &spiceResp, nil
}

func launchSPICEClient(config SPICEConfig, spiceDetails *SPICEResponse) error {
	fmt.Printf("SPICE connection details:\n")
	fmt.Printf("  Host: %s\n", spiceDetails.Data.Host)
	fmt.Printf("  TLS Port: %d\n", spiceDetails.Data.TLSPort)
	fmt.Printf("  Proxy: %s\n", spiceDetails.Data.Proxy)
	fmt.Printf("  Type: %s\n", spiceDetails.Data.Type)

	// Create temporary .vv file
	vvContent := fmt.Sprintf(`[virt-viewer]
toggle-fullscreen=Shift+F11
proxy=%s
release-cursor=Ctrl+Alt+R
delete-this-file=1
title=%s
type=spice
host=%s
host-subject=%s
password=%s
ca=%s
tls-port=%d
secure-attention=Ctrl+Alt+Ins
`,
		spiceDetails.Data.Proxy,
		spiceDetails.Data.Title,
		spiceDetails.Data.Host,
		spiceDetails.Data.HostSubject,
		spiceDetails.Data.Password,
		spiceDetails.Data.CA,
		spiceDetails.Data.TLSPort) // Using host as CA placeholder; adjust as needed)

	//fmt.Print(vvContent)
	// Create temporary file
	tempDir := os.TempDir()
	timestamp := time.Now().Format("20060102-150405")
	vvFileName := filepath.Join(tempDir, fmt.Sprintf("proxmox-spice-%s.vv", timestamp))

	err := os.WriteFile(vvFileName, []byte(vvContent), 0600)
	if err != nil {
		return fmt.Errorf("failed to create .vv file: %w", err)
	}

	fmt.Printf("Created SPICE config file: %s\n", vvFileName)

	// Launch SPICE client with the .vv file
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command(config.ClientPath, vvFileName)
	case "linux", "darwin":
		cmd = exec.Command(config.ClientPath, vvFileName)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	fmt.Printf("Launching SPICE client: %s\n", cmd.String())

	err = cmd.Start()
	if err != nil {
		// Clean up the temp file if launch fails
		//os.Remove(vvFileName)
		return fmt.Errorf("failed to start SPICE client: %w", err)
	}

	// Note: We don't remove the temp file here because remote-viewer might need it
	// The delete-this-file=1 option should make remote-viewer clean it up automatically

	return nil
}

func getDefaultSPICEClient() string {
	switch runtime.GOOS {
	case "windows":
		// Common Windows SPICE client paths
		paths := []string{
			"C:\\Program Files\\VirtViewer\\bin\\remote-viewer.exe",
			"C:\\Program Files (x86)\\VirtViewer\\bin\\remote-viewer.exe",
			"remote-viewer.exe",
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		return "remote-viewer.exe"
	case "linux":
		return "remote-viewer"
	case "darwin":
		return "/Applications/RemoteViewer.app/Contents/MacOS/RemoteViewer"
	default:
		return "remote-viewer"
	}
}
