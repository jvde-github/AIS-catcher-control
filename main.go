package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"html/template"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"runtime"
    "strconv"
	"github.com/shirou/gopsutil/v3/process"
    "github.com/shirou/gopsutil/v3/cpu"
)

var (
    buildVersion = "dev"    // This will be set during build
)

// Embedding the templates and static files

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

const (
	defaultUsername    = "admin"
	defaultPassword    = "admin"
	sessionCookieName  = "session_id"
	configJSONFilePath = "/etc/AIS-catcher/config.json"
	configCmdFilePath  = "/etc/AIS-catcher/config.cmd"
	settingsFilePath   = "/etc/AIS-catcher/control.json"
	logTxtFilePath     = "/etc/AIS-catcher/log.txt"
)

var (
	cssVersion string
	jsVersion  string
)

type SystemInfo struct {
    AISCatcherVersion     string `json:"ais_catcher_version"`      // Full version string
    AISCatcherVersionCode int    `json:"ais_catcher_version_code"` // Numeric version
    AISCatcherDescribe    string `json:"ais_catcher_describe"`     // Detailed version info
    AISCatcherAvailable   bool   `json:"ais_catcher_available"`    // Is AIS-catcher installed
    OS                    string `json:"os"`                        // Operating system
    Architecture          string `json:"architecture"`              // CPU architecture
    CPUInfo              string `json:"cpu_info"`                  // CPU information
    TotalMemory          uint64 `json:"total_memory"`              // Total system memory
    KernelVersion        string `json:"kernel_version"`            // Linux kernel version
    ServiceStatus        string `json:"service_status"`            // systemd service status
    DockerMode           bool   `json:"docker_mode"`               // Running in Docker
	BuildVersion         string `json:"build_version"`             // Git version/build info
	ProcessID            int32     `json:"process_id"`
    ProcessMemoryUsage   float64   `json:"process_memory_usage"`  // in MB
    ProcessCPUUsage      float64   `json:"process_cpu_usage"`     // percentage
    ProcessStartTime     time.Time `json:"process_start_time"`
    ProcessThreadCount   int32     `json:"process_thread_count"`
    SystemCPUUsage      float64   `json:"system_cpu_usage"`      // percentage
    SystemMemoryUsage   float64   `json:"system_memory_usage"`   // percentage
}


var configIntegrityError = false

var templates *template.Template

type LogMessage struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}

type Control struct {
	CssVersion      string   `json:"css_version"`
	JsVersion       string   `json:"js_version"`
	Title           string   `json:"title"`
	Status          string   `json:"status"`
	Uptime          string   `json:"uptime"`
	Logs            []string `json:"logs"`
	LogTxtLogs      []string `json:"log_txt_logs"`
	ServiceEnabled  bool     `json:"service_enabled"`
	Docker          bool     `json:"docker"`
	ContentTemplate string   `json:"content_template"`
}

type ConfigJSON struct {
	Service ServiceConfig `json:"server"`
}

type ServiceConfig struct {
	Port string `json:"port"`
}

var systemInfo SystemInfo

func findAISCatcherPID() (int32, error) {
    processes, err := process.Processes()
    if err != nil {
        return 0, err
    }

    for _, p := range processes {
        name, err := p.Name()
        if err != nil {
            continue
        }
        if name == "AIS-catcher" {
            return p.Pid, nil
        }
    }
    return 0, fmt.Errorf("AIS-catcher process not found")
}

func collectSystemInfo() {

	systemInfo.BuildVersion = buildVersion
	
	if pid, err := findAISCatcherPID(); err == nil {
        systemInfo.ProcessID = pid
        if proc, err := process.NewProcess(pid); err == nil {
            // Memory usage
            if memInfo, err := proc.MemoryInfo(); err == nil {
                systemInfo.ProcessMemoryUsage = float64(memInfo.RSS) / 1024 / 1024 // Convert to MB
            }

            // CPU usage
            if cpuPercent, err := proc.CPUPercent(); err == nil {
                systemInfo.ProcessCPUUsage = cpuPercent
            }

            // Start time
            if createTime, err := proc.CreateTime(); err == nil {
                systemInfo.ProcessStartTime = time.Unix(createTime/1000, 0)
            }

            // Thread count
            if numThreads, err := proc.NumThreads(); err == nil {
                systemInfo.ProcessThreadCount = numThreads
            }
        }
    }

    // System-wide CPU usage
    if cpuPercent, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercent) > 0 {
        systemInfo.SystemCPUUsage = cpuPercent[0]
    }

    // Keep existing system info collection
    systemInfo.OS = runtime.GOOS
    systemInfo.Architecture = runtime.GOARCH
	
	cmd := exec.Command("/usr/bin/AIS-catcher", "-h", "JSON")
    output, err := cmd.CombinedOutput()
	firstLine := strings.Split(string(output), "\n")[0]
    
    if err != nil {
        log.Printf("Command error: %v", err)
        if exitErr, ok := err.(*exec.ExitError); ok {
            log.Printf("Exit error code: %d", exitErr.ExitCode())
            systemInfo.AISCatcherAvailable = true
            systemInfo.AISCatcherVersion = "v0.60 or earlier"
            systemInfo.AISCatcherVersionCode = -1
            systemInfo.AISCatcherDescribe = "Version before JSON support"
        } else {
            systemInfo.AISCatcherAvailable = false
            systemInfo.AISCatcherVersion = "not installed"
            systemInfo.AISCatcherVersionCode = 0
            systemInfo.AISCatcherDescribe = "Not found in system"
        }
	} else {
		var jsonOutput map[string]interface{}
		if err := json.Unmarshal([]byte(firstLine), &jsonOutput); err != nil {
			log.Printf("JSON unmarshal error: %v", err)
			systemInfo.AISCatcherAvailable = true
			systemInfo.AISCatcherVersion = "unknown"
			systemInfo.AISCatcherVersionCode = -1
			systemInfo.AISCatcherDescribe = "Invalid JSON output"
		} else {
			systemInfo.AISCatcherAvailable = true
			systemInfo.AISCatcherVersion = jsonOutput["version"].(string)
			systemInfo.AISCatcherVersionCode = int(jsonOutput["version_code"].(float64))
			systemInfo.AISCatcherDescribe = jsonOutput["version_describe"].(string)
		}
	}

    // Get OS and Architecture
    systemInfo.OS = runtime.GOOS
    systemInfo.Architecture = runtime.GOARCH

    // Get CPU Info
    if cpuinfo, err := ioutil.ReadFile("/proc/cpuinfo"); err == nil {
        scanner := bufio.NewScanner(strings.NewReader(string(cpuinfo)))
        for scanner.Scan() {
            line := scanner.Text()
            if strings.HasPrefix(line, "model name") {
                systemInfo.CPUInfo = strings.TrimSpace(strings.Split(line, ":")[1])
                break
            }
        }
    }

    // Get Memory Info
    if meminfo, err := ioutil.ReadFile("/proc/meminfo"); err == nil {
        scanner := bufio.NewScanner(strings.NewReader(string(meminfo)))
        for scanner.Scan() {
            line := scanner.Text()
            if strings.HasPrefix(line, "MemTotal:") {
                fields := strings.Fields(line)
                if len(fields) >= 2 {
                    if mem, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
                        systemInfo.TotalMemory = mem * 1024 // Convert from KB to bytes
                    }
                }
                break
            }
        }
    }

    // Get Kernel Version
    if kernel, err := exec.Command("uname", "-r").Output(); err == nil {
        systemInfo.KernelVersion = strings.TrimSpace(string(kernel))
    }

    // Get service status
    systemInfo.ServiceStatus = getServiceStatus()
    systemInfo.DockerMode = config.Docker
}

func init() {
	funcMap := template.FuncMap{
		"dynamicTemplate": func(name string, data interface{}) (template.HTML, error) {
			var buf strings.Builder
			err := templates.ExecuteTemplate(&buf, name, data)
			return template.HTML(buf.String()), err
		},
	}

	templates = template.New("").Funcs(funcMap)

	var err error
	templates, err = templates.ParseFS(templatesFS,
		"templates/layout.html",
		"templates/login.html",
		"templates/content/control.html",
		"templates/content/udp-channels.html",
		"templates/content/tcp-channels.html",
		"templates/content/http-channels.html",
		"templates/content/sharing-channel.html",
		"templates/content/change-password.html",
		"templates/content/input-selection.html",
		"templates/content/device-setup.html",
		"templates/content/integrity-error.html",
		"templates/content/server-setup.html",
		"templates/content/webviewer.html",
		"templates/content/support.html",
		"templates/content/edit-config-json.html",
		"templates/content/edit-config-cmd.html",
	)
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
}

var sessions = map[string]string{}

type Config struct {
	PasswordHash   string `json:"password_hash"`
	Port           string `json:"port"`
	ConfigCmdHash  uint32 `json:"config_cmd_hash"`
	ConfigJSONHash uint32 `json:"config_json_hash"`
	Docker         bool   `json:"docker"`
}

var config Config
var execDir string

func initPaths() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	execDir = filepath.Dir(execPath)

	log.Printf("Executable directory: %s", execDir)
	log.Printf("Settings file path: %s", settingsFilePath)
	log.Printf("Config JSON file path: %s", configJSONFilePath)

	return nil
}

func hashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

func loadControlSettings() error {
	data, err := ioutil.ReadFile(settingsFilePath)
	if os.IsNotExist(err) {
		config = Config{
			PasswordHash:   hashPassword(defaultPassword),
			Port:           "8110",
			ConfigCmdHash:  435605018,
			ConfigJSONHash: 3798370746,
			Docker:         false,
		}
		return saveControlSettings()
	} else if err != nil {
		return err
	} else {
		err = json.Unmarshal(data, &config)
		if err != nil {
			return err
		}
	}
	return nil
}

func saveControlSettings() error {
	data, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(settingsFilePath, data, 0644)
}

func calculate32BitHash(input string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(input))
	return h.Sum32()
}

func updateConfigJSONHash(input string) error {
	hashValue := calculate32BitHash(input)

	config.ConfigJSONHash = uint32(hashValue)
	err := saveControlSettings()
	if err != nil {
		return fmt.Errorf("failed to save control settings: %v", err)
	}

	return nil
}

// Authentication functions

func authenticate(username, password string) bool {
	if username != defaultUsername {
		return false
	}
	return hashPassword(password) == config.PasswordHash
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"CssVersion": cssVersion,
			"JsVersion":  jsVersion,
			"message":    "",
		}
		templates.ExecuteTemplate(w, "login.html", data)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if authenticate(username, password) {
		sessionID := hashPassword(username + password)
		sessions[sessionID] = username
		http.SetCookie(w, &http.Cookie{
			Name:  sessionCookieName,
			Value: sessionID,
			Path:  "/",
		})

		if password == defaultPassword && hashPassword(password) == config.PasswordHash {
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/control", http.StatusSeeOther)
		}
	} else {
		data := map[string]interface{}{
			"CssVersion": cssVersion,
			"JsVersion":  jsVersion,
			"message":    "Invalid credentials",
		}
		templates.ExecuteTemplate(w, "login.html", data)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		delete(sessions, cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:   sessionCookieName,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || sessions[cookie.Value] != defaultUsername {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"Title":           "Change Password",
			"ContentTemplate": "change-password",
			"message":         "",
		}

		templates.ExecuteTemplate(w, "layout.html", data)
		return
	}

	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword != confirmPassword {
		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"Title":           "Change Password",
			"ContentTemplate": "change-password",
			"message":         "Passwords do not match",
		}

		templates.ExecuteTemplate(w, "layout.html", data)

		return
	}

	config.PasswordHash = hashPassword(newPassword)
	err := saveControlSettings()
	if err != nil {
		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"Title":           "Change Password",
			"ContentTemplate": "change-password",
			"message":         "Failed to save new password",
		}

		templates.ExecuteTemplate(w, "layout.html", data)
		return
	}

	// Update session
	cookie, _ := r.Cookie(sessionCookieName)
	sessions[cookie.Value] = defaultUsername

	http.Redirect(w, r, "/control", http.StatusSeeOther)
}

func deviceListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Execute the AIS-catcher command
	cmd := exec.Command("/usr/bin/AIS-catcher", "-l", "JSON", "ON")
	stdout, err := cmd.Output()
	if err != nil {
		log.Printf("Error executing AIS-catcher: %v", err)
		http.Error(w, "Failed to retrieve devices information", http.StatusInternalServerError)
		return
	}

	var jsonData interface{}
	err = json.Unmarshal(stdout, &jsonData)
	if err != nil {
		log.Printf("Invalid JSON from AIS-catcher: %v", err)
		http.Error(w, "Invalid JSON data received from AIS-catcher", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(stdout)
}

func serialListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	devices := []string{}

	// Add USB serial devices from by-id if directory exists
	if entries, err := os.ReadDir("/dev/serial/by-id"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				devices = append(devices, "/dev/serial/by-id/"+entry.Name())
			}
		}
	}

	// Check /dev for serial devices
	if entries, err := os.ReadDir("/dev"); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			// Common serial device patterns
			if strings.HasPrefix(name, "ttyUSB") || // USB serial devices
				strings.HasPrefix(name, "ttyACM") || // USB ACM devices
				strings.HasPrefix(name, "ttyAMA") || // Raspberry Pi and others
				strings.HasPrefix(name, "ttyS") || // Standard serial ports
				name == "serial0" || name == "serial1" { // Raspberry Pi aliases

				devicePath := "/dev/" + name
				// Verify it's a character device
				if stat, err := os.Stat(devicePath); err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
					devices = append(devices, devicePath)
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}
func controlHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	journalctlLogs := getServiceLogs(50)
	logTxtLogs := getLogTxtLogs(10)

	controlData := Control{
		CssVersion:      cssVersion,
		JsVersion:       jsVersion,
		Title:           "Control Dashboard",
		Logs:            journalctlLogs,
		LogTxtLogs:      logTxtLogs,
		Docker:          config.Docker,
		ContentTemplate: "control",
	}

	err := templates.ExecuteTemplate(w, "layout.html", controlData)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func getServiceStatus() string {
	if config.Docker {

		cmd := exec.Command("/usr/bin/is-running.sh")
		output, _ := cmd.Output()

		exitCode := cmd.ProcessState.ExitCode()

		if exitCode == 1 {
			return "inactive (stopped)"
		} else if exitCode == 0 {
			return "active (running)"
		} else {
			return "unknown"
		}
		return strings.TrimSpace(string(output))
	}

	cmd := exec.Command("systemctl", "is-active", "ais-catcher.service")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 3 {
				return "inactive (stopped)"
			}
		}
		return "unknown"
	}

	status := strings.TrimSpace(string(output))
	if status == "active" {
		return "active (running)"
	}
	return status
}

func getServiceUptime() string {
	if config.Docker {
		cmd := exec.Command("/usr/bin/uptime.sh")
		output, err := cmd.Output()
		if err != nil {
			return "Unknown"
		}
		return strings.TrimSpace(string(output))
	}

	cmd := exec.Command("systemctl", "show", "ais-catcher.service", "--property=ActiveEnterTimestamp")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	line := strings.TrimSpace(string(output))
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "Unknown"
	}
	timestamp := parts[1]
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", timestamp)
	if err != nil {
		return "Unknown"
	}
	duration := time.Since(t)
	return fmt.Sprintf("%s (since %s)", formatDuration(duration), t.Format("Jan 2, 2006 15:04:05"))
}

func formatDuration(d time.Duration) string {
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}
	return strings.Join(parts, " ")
}

func getServiceLogs(lines int) []string {
	if config.Docker {
		return []string{""}
	}

	cmd := exec.Command("journalctl", "-u", "ais-catcher.service", "-n", fmt.Sprintf("%d", lines), "--no-pager", "--output=cat")
	output, err := cmd.Output()
	if err != nil {
		return []string{"Unable to retrieve logs"}
	}

	logLines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return logLines
}

func getLogTxtLogs(lines int) []string {

	cmd := exec.Command("tail", "-n", fmt.Sprintf("%d", lines), logTxtFilePath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if strings.Contains(stderr.String(), "No such file or directory") {
			return []string{""}
		}
		log.Printf("Error executing tail command: %v, %s", err, stderr.String())
		return []string{"Error reading %s.", logTxtFilePath}
	}

	// Get the command output as a string
	output := stdout.String()

	// Handle the case where the file is empty
	if strings.TrimSpace(output) == "" {
		return []string{"%s is empty.", logTxtFilePath}
	}

	// Split the output into individual lines
	logLines := strings.Split(strings.TrimSpace(output), "\n")
	return logLines
}

func controlService(action string) error {
	if config.Docker {
		// Use custom scripts for control if in Docker mode
		script := fmt.Sprintf("/usr/bin/%s.sh", action)
		fmt.Println("Running script:", script)
		cmd := exec.Command(script)
		return cmd.Run()
	}

	// Fallback to systemctl if not in Docker mode
	cmd := exec.Command("systemctl", action, "ais-catcher.service")
	return cmd.Run()
}

func getServiceEnabled() (bool, error) {
	if config.Docker {
		// Use custom scripts for control if in Docker mode
		cmd := exec.Command("/usr/bin/is-enabled.sh")
		output, _ := cmd.Output()
		status := strings.TrimSpace(string(output))
		return status == "enabled", nil
	}
	cmd := exec.Command("systemctl", "is-enabled", "ais-catcher.service")
	output, err := cmd.Output()
	status := strings.TrimSpace(string(output))

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				return false, nil
			}
		}
		return false, err
	}

	return status == "enabled", nil
}

func sanitizeFileContent(content string) string {
	// Implement any necessary sanitization here
	// For example, remove unwanted characters or validate JSON if editing config.json
	return content
}

func sanitizeLogLine(line string) string {
	var sanitized strings.Builder
	for _, r := range line {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			sanitized.WriteRune(r)
		}
	}
	return sanitized.String()
}

func readConfigJSON() ([]byte, error) {
	jsonContent, err := ioutil.ReadFile(configJSONFilePath)
	if err != nil {
		log.Printf("Error reading config.json: %v", err)
		return []byte(""), err
	}

	calculatedHash := calculate32BitHash(string(jsonContent))

	if uint32(calculatedHash) != config.ConfigJSONHash {
		fmt.Printf("hash mismatch: config.json content does not match the stored hash (%d != %d)\n", calculatedHash, config.ConfigJSONHash)
		configIntegrityError = true
	}

	return jsonContent, nil
}

func readConfigCmd() ([]byte, error) {
	cmdContent, err := ioutil.ReadFile(configCmdFilePath)
	if err != nil {
		log.Printf("Error reading config.cmd: %v", err)
		return []byte(""), err
	}

	calculatedHash := calculate32BitHash(string(cmdContent))

	if uint32(calculatedHash) != config.ConfigCmdHash {
		fmt.Printf("hash mismatch: config.cmd content does not match the stored hash (%d != %d)\n", calculatedHash, config.ConfigCmdHash)
		configIntegrityError = true
	}

	return cmdContent, nil
}

func saveConfigJSON(w http.ResponseWriter, r *http.Request) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("Failed to read request body: %v", err)
	}

	// Validate the JSON data
	var jsonMap map[string]interface{}
	err = json.Unmarshal(body, &jsonMap)
	if err != nil {
		return fmt.Errorf("Invalid JSON: %v", err)
	}

	// Check that "config" is "aiscatcher" and "version" is 1
	configValue, ok := jsonMap["config"].(string)
	if !ok || configValue != "aiscatcher" {
		return fmt.Errorf("Invalid JSON: config value must be 'aiscatcher'")
	}

	versionValue, ok := jsonMap["version"].(float64)
	if !ok || int(versionValue) != 1 {
		return fmt.Errorf("Invalid JSON: version value must be 1")
	}

	hashValue := calculate32BitHash(string(body))
	err = loadControlSettings()
	if err != nil {
		return fmt.Errorf("Failed to load control settings: %v", err)
	}

	config.ConfigJSONHash = uint32(hashValue)
	err = saveControlSettings()

	if err != nil {
		return fmt.Errorf("Failed to update control settings with new hash: %v", err)
	}

	err = ioutil.WriteFile(configJSONFilePath, body, 0644)
	if err != nil {
		return fmt.Errorf("Failed to save config.json: %v", err)
	}

	return nil
}

func sendSSE(w http.ResponseWriter, msg LogMessage) {
	jsonData, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshaling log message: %v", err)
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", jsonData)
}

func sendHeartbeat(w http.ResponseWriter, flusher http.Flusher, ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// Broadcaster manages log collection and client subscriptions
type Broadcaster struct {
	journalChan chan string
	logtxtChan  chan string
	clients     map[chan LogMessage]bool
	mu          sync.Mutex
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		journalChan: make(chan string, 100),
		logtxtChan:  make(chan string, 100),
		clients:     make(map[chan LogMessage]bool),
	}
}

func (b *Broadcaster) Run() {
	go b.collectJournalctlLogs()
	go b.collectLogTxtLogs()

	for {
		select {
		case journalLine := <-b.journalChan:
			msg := LogMessage{
				Source:  "journalctl",
				Message: sanitizeLogLine(journalLine),
			}
			b.broadcast(msg)
		case logtxtLine := <-b.logtxtChan:
			msg := LogMessage{
				Source:  "log.txt",
				Message: sanitizeLogLine(logtxtLine),
			}
			b.broadcast(msg)
		}
	}
}

func (b *Broadcaster) collectJournalctlLogs() {
	cmd := exec.Command("journalctl", "-u", "ais-catcher.service", "-n", "0", "-f", "--no-pager", "--output=cat")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Error obtaining stdout pipe for journalctl: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("Error starting journalctl command: %v", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		b.journalChan <- line
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading journalctl output: %v", err)
	}
}

func (b *Broadcaster) collectLogTxtLogs() {
	for {
		cmd := exec.Command("tail", "-F", logTxtFilePath)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("Error obtaining stdout pipe for tail: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		if err := cmd.Start(); err != nil {
			log.Printf("Error starting tail command: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			b.logtxtChan <- line
		}

		if err := scanner.Err(); err != nil {
			log.Printf("Error reading tail output: %v", err)
		}

		cmd.Wait()

		log.Println("Restarting tail command for log.txt")

		time.Sleep(1 * time.Second)
	}
}

func (b *Broadcaster) broadcast(msg LogMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for clientChan := range b.clients {
		select {
		case clientChan <- msg:
		default:
			// If the client's channel is full, remove the client
			close(clientChan)
			delete(b.clients, clientChan)
		}
	}
}

func (b *Broadcaster) Subscribe() chan LogMessage {
	clientChan := make(chan LogMessage, 100)
	b.mu.Lock()
	b.clients[clientChan] = true
	b.mu.Unlock()
	return clientChan
}

func (b *Broadcaster) Unsubscribe(clientChan chan LogMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.clients[clientChan]; exists {
		close(clientChan)
		delete(b.clients, clientChan)
	}
}

func logsStreamHandler(w http.ResponseWriter, r *http.Request, broadcaster *Broadcaster) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	// Subscribe to the broadcaster
	clientChan := broadcaster.Subscribe()
	defer broadcaster.Unsubscribe(clientChan)

	// Start sending heartbeats
	go sendHeartbeat(w, flusher, ctx)

	// Listen for log messages and send them to the client
	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			return
		case msg, ok := <-clientChan:
			if !ok {
				return
			}
			jsonData, err := json.Marshal(msg)
			if err != nil {
				log.Printf("Error marshaling log message: %v", err)
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", jsonData)
			flusher.Flush()
		}
	}
}

func checkTailCommand() error {
	_, err := exec.LookPath("tail")
	if err != nil {
		return fmt.Errorf("tail command not found in PATH")
	}
	return nil
}

func udpChannelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /udp")
		renderTemplateWithConfig(w, "UDP channels", "udp-channels")

	} else if r.Method == http.MethodPost {
		err := saveConfigJSON(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Send success response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Configuration saved successfully."))
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

func deviceSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /device")
		renderTemplateWithConfig(w, "Device Configuration", "device-setup")
	} else if r.Method == http.MethodPost {
		// Handle POST request to save JSON data
		err := saveConfigJSON(w, r)
		if err != nil {
			// Send error response
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Send success response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Configuration saved successfully."))
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

func sharingChannelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /sharing")
		renderTemplateWithConfig(w, "Community Sharing", "sharing-channel")
	} else if r.Method == http.MethodPost {
		// Handle POST request to save JSON data
		err := saveConfigJSON(w, r)
		if err != nil {
			// Send error response
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Send success response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Configuration saved successfully."))
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

func renderTemplateWithConfig(w http.ResponseWriter, title string, contentTemplate string) {
	jsonContent, err := readConfigJSON()
	if err != nil {
		log.Printf("Error reading config.json: %v", err)
		jsonContent = []byte("")
	}

	if true && configIntegrityError {
		data := map[string]interface{}{
			"Title":           "Configuration Integrity Error",
			"ContentTemplate": "integrity-error",
		}
		err := templates.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error for integrity-error: %v", err)
		}
		return
	}

	data := map[string]interface{}{
		"CssVersion":      cssVersion,
		"JsVersion":       jsVersion,
		"JsonContent":     string(jsonContent),
		"Title":           title,
		"ContentTemplate": contentTemplate,
	}

	err = templates.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func inputSelectionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /input")
		renderTemplateWithConfig(w, "Input Selection", "input-selection")

	} else if r.Method == http.MethodPost {
		err := saveConfigJSON(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Send success response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Configuration saved successfully."))
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

func webviewerHandler(w http.ResponseWriter, r *http.Request) {
	jsonContent, err := readConfigJSON()
	if err != nil {
		log.Printf("Error reading config.json: %v", err)
		jsonContent = []byte("")
	}

	port := "8000"

	if len(jsonContent) > 0 {
		var cfg ConfigJSON
		err = json.Unmarshal(jsonContent, &cfg)
		if err != nil {
			log.Printf("Error parsing config.json: %v", err)
		} else {
			port = cfg.Service.Port
		}
	}

	data := map[string]interface{}{
		"CssVersion":      cssVersion,
		"JsVersion":       jsVersion,
		"JsonContent":     string(jsonContent),
		"Title":           "Webviewer",
		"ContentTemplate": "webviewer",
		"port":            port,
	}

	err = templates.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func serverSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /server")
		renderTemplateWithConfig(w, "Webviewer Setup", "server-setup")

	} else if r.Method == http.MethodPost {
		err := saveConfigJSON(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Send success response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Configuration saved successfully."))
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

func tcpChannelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /tcp")
		renderTemplateWithConfig(w, "TCP Channels", "tcp-channels")

	} else if r.Method == http.MethodPost {
		err := saveConfigJSON(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Configuration saved successfully."))
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

func httpChannelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /http")
		renderTemplateWithConfig(w, "HTTP Channels", "http-channels")

	} else if r.Method == http.MethodPost {
		err := saveConfigJSON(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Configuration saved successfully."))
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}


func getFileVersion(staticFSys fs.FS, filepath string) string {
	f, err := staticFSys.Open(filepath)
	if err != nil {
		log.Printf("Error opening %s for versioning: %v", filepath, err)
		return ""
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		log.Printf("Error reading %s for versioning: %v", filepath, err)
		return ""
	}

	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])[:8]
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	status := getServiceStatus()
	uptime := getServiceUptime()
	enabled, _ := getServiceEnabled()

	data := map[string]interface{}{
		"status":  status,
		"uptime":  uptime,
		"enabled": enabled,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func serviceHandler(w http.ResponseWriter, r *http.Request) {

	action := r.URL.Query().Get("action")

	validActions := map[string]bool{
		"start":   true,
		"stop":    true,
		"restart": true,
		"enable":  true,
		"disable": true,
	}

	if !validActions[action] {
		http.Redirect(w, r, "/control", http.StatusSeeOther)
		return
	}

	err := controlService(action)
	if err != nil {
		log.Println("Service control error:", err)
	}

	data := map[string]interface{}{
		"status": true,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func editConfigJSONHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Read config.json
		jsonContent, err := readConfigJSON()
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			jsonContent = []byte("")
		}

		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"FileContent":     string(jsonContent),
			"Title":           "Edit config.json",
			"ContentTemplate": "edit-config-json",
		}

		err = templates.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", err)
		}

	} else if r.Method == http.MethodPost {
		// Read new content from form
		newContent := r.FormValue("file_content")

		// Validate JSON
		var jsonMap map[string]interface{}
		err := json.Unmarshal([]byte(newContent), &jsonMap)
		if err != nil {
			data := map[string]interface{}{
				"CssVersion":      cssVersion,
				"JsVersion":       jsVersion,
				"FileContent":     newContent,
				"Title":           "Edit config.json",
				"ContentTemplate": "edit-config-json",
				"ErrorMessage":    "Invalid JSON: " + err.Error(),
			}
			err = templates.ExecuteTemplate(w, "layout.html", data)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Printf("Template execution error: %v", err)
			}
			return
		}

		// Save the file
		err = ioutil.WriteFile(configJSONFilePath, []byte(newContent), 0644)
		if err != nil {
			data := map[string]interface{}{
				"CssVersion":      cssVersion,
				"JsVersion":       jsVersion,
				"FileContent":     newContent,
				"Title":           "Edit config.json",
				"ContentTemplate": "edit-config-json",
				"ErrorMessage":    "Failed to save file: " + err.Error(),
			}
			err = templates.ExecuteTemplate(w, "layout.html", data)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Printf("Template execution error: %v", err)
			}
			return
		}

		// Update hash value
		config.ConfigJSONHash = uint32(0)
		err = saveControlSettings()
		if err != nil {
			data := map[string]interface{}{
				"CssVersion":      cssVersion,
				"JsVersion":       jsVersion,
				"FileContent":     newContent,
				"Title":           "Edit config.json",
				"ContentTemplate": "edit-config-json",
				"ErrorMessage":    "Failed to update control settings: " + err.Error(),
			}
			err = templates.ExecuteTemplate(w, "layout.html", data)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Printf("Template execution error: %v", err)
			}
			return
		}

		// Display success message
		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"FileContent":     newContent,
			"Title":           "Edit config.json",
			"ContentTemplate": "edit-config-json",
			"SuccessMessage":  "Configuration saved successfully.",
		}
		err = templates.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", err)
		}

	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func editConfigCMDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Read config.cmd
		cmdContent, err := ioutil.ReadFile(configCmdFilePath)
		if err != nil {
			log.Printf("Error reading config.cmd: %v", err)
			cmdContent = []byte("")
		}

		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"FileContent":     string(cmdContent),
			"Title":           "Edit config.cmd",
			"ContentTemplate": "edit-config-cmd",
		}

		err = templates.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", err)
		}

	} else if r.Method == http.MethodPost {
		// Read new content from form
		newContent := r.FormValue("file_content")

		// Optionally sanitize the content
		sanitizedContent := sanitizeFileContent(newContent)

		// Save the file
		err := ioutil.WriteFile(configCmdFilePath, []byte(sanitizedContent), 0644)
		if err != nil {
			data := map[string]interface{}{
				"CssVersion":      cssVersion,
				"JsVersion":       jsVersion,
				"FileContent":     newContent,
				"Title":           "Edit config.cmd",
				"ContentTemplate": "edit-config-cmd",
				"ErrorMessage":    "Failed to save file: " + err.Error(),
			}
			err = templates.ExecuteTemplate(w, "layout.html", data)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Printf("Template execution error: %v", err)
			}
			return
		}

		// Update hash value
		config.ConfigCmdHash = uint32(0)
		err = saveControlSettings()
		if err != nil {
			data := map[string]interface{}{
				"CssVersion":      cssVersion,
				"JsVersion":       jsVersion,
				"FileContent":     newContent,
				"Title":           "Edit config.cmd",
				"ContentTemplate": "edit-config-cmd",
				"ErrorMessage":    "Failed to update control settings: " + err.Error(),
			}
			err = templates.ExecuteTemplate(w, "layout.html", data)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Printf("Template execution error: %v", err)
			}
			return
		}

		// Display success message
		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"FileContent":     sanitizedContent,
			"Title":           "Edit config.cmd",
			"ContentTemplate": "edit-config-cmd",
			"SuccessMessage":  "Configuration saved successfully.",
		}
		err = templates.ExecuteTemplate(w, "layout.html", data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", err)
		}

	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

type SystemInfoTemplate struct {
    SystemInfo    SystemInfo
    MemoryGB     float64
    CssVersion   string
    JsVersion    string
}

func systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	collectSystemInfo()
	
    memoryGB := float64(systemInfo.TotalMemory) / 1073741824.0
    
    err := templates.ExecuteTemplate(w, "layout.html", map[string]interface{}{
        "CssVersion":      cssVersion,
        "JsVersion":       jsVersion,
        "Title":           "System Information",
        "ContentTemplate": "support",
        "SystemInfo":      systemInfo,
        "MemoryGB":       memoryGB,
    })
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        log.Printf("Template execution error: %v", err)
    }
}


func main() {

	collectSystemInfo()

	if err := checkTailCommand(); err != nil {
		log.Fatalf("Required command not found: %v", err)
	}

	err := initPaths()
	if err != nil {
		log.Fatal("Failed to initialize paths:", err)
	}

	err = loadControlSettings()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// message if running in Docker mode
	if config.Docker {
		log.Println("Running in Docker mode")
	}

	staticFSys, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal("Failed to create sub filesystem:", err)
	}

	cssVersion = getFileVersion(staticFSys, "css/tailwind.css")
	jsVersion = getFileVersion(staticFSys, "js/scripts.js")

	_, err = readConfigJSON()
	if err != nil {
		log.Fatal("Failed to read config.json:", err)
	}

	_, err = readConfigCmd()
	if err != nil {
		log.Fatal("Failed to read config.cmd:", err)
	}

	// Initialize the broadcaster
	broadcaster := NewBroadcaster()
	go broadcaster.Run()

	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		http.StripPrefix("/static/", http.FileServer(http.FS(staticFSys))).ServeHTTP(w, r)
	})

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/sharing", authMiddleware(sharingChannelsHandler))
	http.HandleFunc("/udp", authMiddleware(udpChannelsHandler))
	http.HandleFunc("/tcp", authMiddleware(tcpChannelsHandler))
	http.HandleFunc("/http", authMiddleware(httpChannelsHandler))
	http.HandleFunc("/control", authMiddleware(controlHandler))
	http.HandleFunc("/change-password", authMiddleware(changePasswordHandler))
	http.HandleFunc("/service", authMiddleware(serviceHandler))
	http.HandleFunc("/logs-stream", authMiddleware(func(w http.ResponseWriter, r *http.Request) { logsStreamHandler(w, r, broadcaster) }))
	http.HandleFunc("/status", authMiddleware(statusHandler))
	http.HandleFunc("/device", authMiddleware(deviceSetupHandler))
	http.HandleFunc("/server", authMiddleware(serverSetupHandler))
	http.HandleFunc("/input", authMiddleware(inputSelectionHandler))
	http.HandleFunc("/webviewer", authMiddleware(webviewerHandler))
	http.HandleFunc("/logout", authMiddleware(logoutHandler))
	http.HandleFunc("/device-list", authMiddleware(deviceListHandler))
	http.HandleFunc("/serial-list", authMiddleware(serialListHandler))
	http.HandleFunc("/editjson", authMiddleware(editConfigJSONHandler))
	http.HandleFunc("/editcmd", authMiddleware(editConfigCMDHandler))
	http.HandleFunc("/support", authMiddleware(systemInfoHandler))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil && sessions[cookie.Value] == defaultUsername {
			http.Redirect(w, r, "/control", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
	})

	addr := ":" + config.Port
	log.Printf("Server started at %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
