package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
)

var (
	buildVersion = "dev" // This will be set during build
	ansiEscape   = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
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
)

var (
	cssVersion string
	jsVersion  string
)

type SystemInfo struct {
	AISCatcherVersion     string    `json:"ais_catcher_version"`      // Full version string
	AISCatcherVersionCode int       `json:"ais_catcher_version_code"` // Numeric version
	AISCatcherDescribe    string    `json:"ais_catcher_describe"`     // Detailed version info
	AISCatcherAvailable   bool      `json:"ais_catcher_available"`    // Is AIS-catcher installed
	OS                    string    `json:"os"`                       // Operating system
	Architecture          string    `json:"architecture"`             // CPU architecture
	CPUInfo               string    `json:"cpu_info"`                 // CPU information
	TotalMemory           uint64    `json:"total_memory"`             // Total system memory
	KernelVersion         string    `json:"kernel_version"`           // Linux kernel version
	ServiceStatus         string    `json:"service_status"`           // systemd service status
	BuildVersion          string    `json:"build_version"`            // Git version/build info
	ProcessID             int32     `json:"process_id"`
	ProcessMemoryUsage    float64   `json:"process_memory_usage"` // in MB
	ProcessCPUUsage       float64   `json:"process_cpu_usage"`    // percentage
	ProcessStartTime      time.Time `json:"process_start_time"`
	ProcessThreadCount    int32     `json:"process_thread_count"`
	SystemCPUUsage        float64   `json:"system_cpu_usage"`    // percentage
	SystemMemoryUsage     float64   `json:"system_memory_usage"` // percentage
}

var templates *template.Template

type LogMessage struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}

type Control struct {
	CssVersion      string `json:"css_version"`
	JsVersion       string `json:"js_version"`
	Title           string `json:"title"`
	Status          string `json:"status"`
	Uptime          string `json:"uptime"`
	ServiceEnabled  bool   `json:"service_enabled"`
	ContentTemplate string `json:"content_template"`
}

type ConfigJSON struct {
	Service ServiceConfig `json:"server"`
}

type ServiceConfig struct {
	Port string `json:"port"`
}

var systemInfo SystemInfo

// Global state for system actions
type SystemActionState struct {
	sync.Mutex
	IsRunning   bool
	ActionName  string
	Logs        []string
	Subscribers map[chan SSEMessage]bool
	Result      *SSEMessage // Store the final result message
}

type SSEMessage struct {
	Type    string
	Content string
}

var globalActionState = SystemActionState{
	Subscribers: make(map[chan SSEMessage]bool),
}

func systemActionStatusHandler(w http.ResponseWriter, r *http.Request) {
	globalActionState.Lock()
	defer globalActionState.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"running": globalActionState.IsRunning,
		"action":  globalActionState.ActionName,
	})
}

func getActionScript(action string) (string, bool) {
	var script string
	var reload bool

	switch action {
	case "system-update":
		script = `echo "Starting system update..." && \
        apt-get update -y && \
        echo "System update completed"`

	case "ais-update-prebuilt":
		script = `echo "Starting AIS-catcher prebuilt update..." && \
        echo "Downloading and executing installation script..." && \
        curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install | bash -s -- -p && \
        echo "AIS-catcher installation completed"`

	case "ais-update-source":
		script = `echo "Starting AIS-catcher source update..." && \
        echo "Downloading and executing installation script..." && \
        curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install | bash && \
        echo "AIS-catcher installation completed"`

	case "control-update":
		script = `echo "Starting AIS-catcher Control update..." && \
        echo "Downloading and executing installation script..." && \
        curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher-control/main/install_ais_catcher_control.sh | bash && \
        echo "AIS-catcher Control installation completed"`
		reload = true

	case "system-reboot":
		script = `echo "Initiating system reboot..." && reboot`
		reload = true

	case "system-halt":
		script = `echo "Initiating system reboot..." && shutdown`
		reload = true

	case "update-all":
		script = `echo "Starting full system update..." && \
        echo "Step 1: Installing AIS-catcher..." && \
        curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install | bash -s -- -p && \
        echo "Step 2: Installing AIS-catcher Control..." && \
        curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher-control/main/install_ais_catcher_control.sh | bash && \
        echo "Full system update completed"`
		reload = true

	case "update-all-reboot":
		script = `echo "Starting full system update with reboot..." && \
        echo "Step 1: Installing AIS-catcher..." && \
        curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install | bash -s -- -p && \
        echo "Step 2: Installing AIS-catcher Control..." && \
        curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher-control/main/install_ais_catcher_control.sh | bash && \
        echo "Full system update completed" && \
        echo "Step 3: Preparing for reboot..." && \
        reboot`
		reload = true
	}

	return script, reload
}

func systemActionProgressHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	requestedAction := r.URL.Query().Get("action")

	globalActionState.Lock()
	if globalActionState.IsRunning {
		// If an action is running, we can only attach to it if the requested action matches
		// or if no specific action was requested (just viewing status)
		if requestedAction != "" && requestedAction != globalActionState.ActionName {
			globalActionState.Unlock()
			sendSSEMessage(w, flusher, "error", "Another system action is already in progress")
			return
		}
		// Proceed to attach
	} else {
		// If not running, we can start a new one if requested
		if requestedAction != "" {
			script, reload := getActionScript(requestedAction)
			if script == "" {
				globalActionState.Unlock()
				sendSSEMessage(w, flusher, "error", "Invalid action")
				return
			}

			// Start new action
			globalActionState.IsRunning = true
			globalActionState.ActionName = requestedAction
			globalActionState.Logs = []string{}
			globalActionState.Result = nil

			// Run in background
			go runSystemAction(requestedAction, script, reload)
		} else {
			// Not running, no action requested -> nothing to do
			globalActionState.Unlock()
			return
		}
	}

	// Subscribe to updates
	msgChan := make(chan SSEMessage, 100)
	globalActionState.Subscribers[msgChan] = true

	// Send history immediately
	history := make([]string, len(globalActionState.Logs))
	copy(history, globalActionState.Logs)

	// If we have a result (finished just now or previously), send it
	var result *SSEMessage
	if globalActionState.Result != nil {
		result = globalActionState.Result
	}

	globalActionState.Unlock()

	// Send history
	for _, log := range history {
		sendSSEMessage(w, flusher, "output", log)
	}

	// If finished, send result and exit
	if result != nil {
		sendSSEMessage(w, flusher, result.Type, result.Content)
		// We don't return here immediately because we might want to keep the connection open?
		// No, if it's done, we are done.
		// But wait, if we just attached to a finished action, we send result and close.
		return
	}

	// Listen for new messages
	// Use r.Context().Done() to detect client disconnect
	ctx := r.Context()

	for {
		select {
		case msg := <-msgChan:
			sendSSEMessage(w, flusher, msg.Type, msg.Content)
			if msg.Type == "complete" || msg.Type == "error" {
				return
			}
		case <-ctx.Done():
			globalActionState.Lock()
			delete(globalActionState.Subscribers, msgChan)
			globalActionState.Unlock()
			return
		}
	}
}

func runSystemAction(actionName, script string, reload bool) {
	// Create a unique unit name for this execution
	unitName := fmt.Sprintf("ais-update-%d", time.Now().UnixNano())

	// Check if systemd is available
	useSystemd := false
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		useSystemd = true
	}

	var runCmd *exec.Cmd
	// We use a background context because this runs independently of the HTTP request
	ctx := context.Background()

	if useSystemd {
		// Set proper unit properties for systemd-run
		runCmd = exec.CommandContext(ctx, "systemd-run",
			"--unit="+unitName,
			"--property=Type=oneshot",
			"--pipe",
			"--collect",
			"/bin/bash", "-c", script)
	} else {
		// Run directly
		runCmd = exec.CommandContext(ctx, "/bin/bash", "-c", script)
	}

	// Set environment variables for systemctl to work properly
	// Copy the parent environment and add critical systemd variables
	runCmd.Env = os.Environ()
	// Ensure systemctl can communicate with systemd even in non-interactive contexts
	runCmd.Env = append(runCmd.Env,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
	)

	stdout, err := runCmd.StdoutPipe()
	if err != nil {
		broadcastResult("error", fmt.Sprintf("Failed to create stdout pipe: %v", err))
		return
	}
	runCmd.Stderr = runCmd.Stdout // Combine stderr into stdout

	if err := runCmd.Start(); err != nil {
		broadcastResult("error", fmt.Sprintf("Failed to start command: %v", err))
		return
	}

	// Stream output
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		log := scanner.Text()
		if log != "" {
			cleanLog := ansiEscape.ReplaceAllString(log, "")
			broadcastLog(cleanLog)
		}
	}

	if err := runCmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			broadcastResult("error", fmt.Sprintf("Command failed with exit code %d", exitErr.ExitCode()))
		} else {
			broadcastResult("error", fmt.Sprintf("Command execution error: %v", err))
		}
	} else {
		broadcastResult("complete", fmt.Sprintf(`{"success": true, "reload": %v}`, reload))
	}
}

func broadcastLog(content string) {
	globalActionState.Lock()
	defer globalActionState.Unlock()

	// Append to history (limit to 1000 lines)
	if len(globalActionState.Logs) >= 1000 {
		globalActionState.Logs = globalActionState.Logs[1:]
	}
	globalActionState.Logs = append(globalActionState.Logs, content)

	msg := SSEMessage{Type: "output", Content: content}
	for ch := range globalActionState.Subscribers {
		// Non-blocking send to avoid hanging if a client is slow
		select {
		case ch <- msg:
		default:
		}
	}
}

func broadcastResult(msgType, content string) {
	globalActionState.Lock()
	defer globalActionState.Unlock()

	globalActionState.IsRunning = false
	result := SSEMessage{Type: msgType, Content: content}
	globalActionState.Result = &result

	for ch := range globalActionState.Subscribers {
		select {
		case ch <- result:
		default:
		}
		// We don't close channels here, the handler loop will see the "complete"/"error" type and return.
		// But we should probably remove them from the map?
		// The handler will remove itself when it returns and defer cleanup isn't there?
		// The handler loop breaks on "complete"/"error", so it will exit.
		// But we need to make sure we don't keep sending to them.
		// Actually, the handler removes itself on ctx.Done(), but if we return from loop, we should also remove.
		// But we can't remove from inside the loop easily without locking again.
		// It's fine, the handler will return, the channel will be garbage collected eventually,
		// but we should clean up the map.
		// Let's just clear the map here since everyone is done.
		delete(globalActionState.Subscribers, ch)
	}
}

func MigrateAISCatcherConfig(jsonData []byte) ([]byte, error) {
	var config map[string]interface{}

	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}

	// Validate it's an AIS-catcher config
	if configType, ok := config["config"].(string); !ok || configType != "aiscatcher" {
		return nil, fmt.Errorf("not a valid AIS-catcher configuration")
	}

	if version, ok := config["version"].(float64); !ok || int(version) != 1 {
		return nil, fmt.Errorf("unsupported configuration version")
	}

	// Receiver-related keys that should be moved to receivers array
	// Based on the C++ Config.cpp parser
	receiverKeys := []string{
		"serial", "input", "verbose", "model", "meta", "own_mmsi",
		"rtlsdr", "rtltcp", "airspy", "airspyhf", "hydrasdr", "sdrplay", "serialport",
		"hackrf", "udpserver", "soapysdr", "nmea2000", "file", "zmq",
		"spyserver", "wavfile",
	}

	// Check if receiver array exists and validate it's actually an array
	var receiverArray []interface{}
	if receiverValue, exists := config["receiver"]; exists {
		// Try to cast to array
		if arr, ok := receiverValue.([]interface{}); ok {
			receiverArray = arr
			log.Printf("Found existing receiver array with %d entries", len(receiverArray))
		} else {
			// receiver exists but is not an array, create new array
			log.Println("Warning: 'receiver' exists but is not an array, creating new array")
			receiverArray = []interface{}{}
		}
	} else {
		// receiver doesn't exist, create new array
		receiverArray = []interface{}{}
	}

	// Extract receiver settings from root
	receiverConfig := make(map[string]interface{})
	hasReceiverSettings := false

	for _, key := range receiverKeys {
		if value, exists := config[key]; exists {
			receiverConfig[key] = value
			delete(config, key)
			hasReceiverSettings = true
			log.Printf("Moved receiver key '%s' from root to receiver config", key)
		}
	}

	// Verify that receiver keys have been removed from root
	for _, key := range receiverKeys {
		if _, stillExists := config[key]; stillExists {
			log.Printf("WARNING: Key '%s' still exists at root after deletion!", key)
		}
	}

	// If there are receiver settings in root, add them as an additional object to the array
	if hasReceiverSettings {
		// Set default input to "rtlsdr" if neither input nor serial are specified
		_, hasInput := receiverConfig["input"]
		_, hasSerial := receiverConfig["serial"]
		if !hasInput && !hasSerial {
			receiverConfig["input"] = "RTLSDR"
			log.Println("No input or serial specified, defaulting to rtlsdr input")
		}

		receiverArray = append(receiverArray, receiverConfig)
		log.Printf("Added receiver settings from root to receiver array")

		// Log which keys were moved
		var movedKeys []string
		for key := range receiverConfig {
			movedKeys = append(movedKeys, key)
		}
		log.Printf("Moved keys: %v", movedKeys)
	}

	// Update config with the receiver array (can be empty)
	config["receiver"] = receiverArray

	// Final verification: check for any receiver keys still at root level
	log.Println("Final config keys at root level:")
	for key := range config {
		log.Printf("  - %s", key)
	}

	return json.MarshalIndent(config, "", "  ")
}

// migrateMsgFormat migrates json/json_full flags to msgformat in channel objects
func migrateMsgFormat(channel map[string]interface{}) bool {
	modified := false

	// Check if msgformat already exists
	if _, exists := channel["msgformat"]; exists {
		// msgformat already set, still remove old keys if present
		if _, hasJSON := channel["json"]; hasJSON {
			delete(channel, "json")
			modified = true
		}
		if _, hasJSONFull := channel["json_full"]; hasJSONFull {
			delete(channel, "json_full")
			modified = true
		}
		return modified
	}

	// Extract json and json_full flags
	jsonFlag, hasJSON := channel["json"].(bool)
	jsonFullFlag, hasJSONFull := channel["json_full"].(bool)

	// Determine msgformat based on flags
	msgFormat := "NMEA" // default

	if hasJSONFull && jsonFullFlag {
		msgFormat = "JSON_FULL"
	} else if hasJSON && jsonFlag {
		msgFormat = "JSON_NMEA"
	}

	// Set msgformat
	channel["msgformat"] = msgFormat
	modified = true

	// Remove old keys
	if hasJSON {
		delete(channel, "json")
	}
	if hasJSONFull {
		delete(channel, "json_full")
	}

	return modified
}

// Add this function to perform one-time migration at startup
func migrateConfigAtStartup() error {
	jsonContent, err := os.ReadFile(configJSONFilePath)
	if err != nil {
		return err
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(jsonContent, &configMap); err != nil {
		return nil // Not valid JSON, skip migration
	}

	// Check if it's an AIS-catcher config
	if configType, ok := configMap["config"].(string); !ok || configType != "aiscatcher" {
		return nil // Not an AIS-catcher config
	}

	needsReceiverMigration := false
	needsMsgFormatMigration := false
	needsServerArrayMigration := false

	// Check if receiver array migration is needed
	// Migration needed if receiver array doesn't exist OR if there are root-level receiver keys
	receiverKeys := []string{
		"serial", "input", "verbose", "model", "meta", "own_mmsi",
		"rtlsdr", "rtltcp", "airspy", "airspyhf", "hydrasdr", "sdrplay", "serialport",
		"hackrf", "udpserver", "soapysdr", "nmea2000", "file", "zmq",
		"spyserver", "wavfile",
	}

	if _, exists := configMap["receiver"]; !exists {
		needsReceiverMigration = true
	} else {
		// Receiver array exists, but check if there are root-level receiver settings
		for _, key := range receiverKeys {
			if _, exists := configMap[key]; exists {
				needsReceiverMigration = true
				log.Printf("Found root-level receiver key '%s' with existing receiver array - migration needed", key)
				break
			}
		}
	}

	// Check if server needs to be converted from object to array
	if serverValue, exists := configMap["server"]; exists {
		// Check if it's an object (map) instead of an array
		if serverObj, isMap := serverValue.(map[string]interface{}); isMap {
			// It's an object, not an array - needs migration
			log.Println("Detected 'server' as object, will migrate to array")
			needsServerArrayMigration = true
			// Convert to array immediately
			configMap["server"] = []interface{}{serverObj}
		}
	}

	// Check if msgformat migration is needed for udp, tcp_listener, tcp arrays
	channelArrays := []string{"udp", "tcp_listener", "tcp"}
	for _, arrayKey := range channelArrays {
		if arrayValue, ok := configMap[arrayKey].([]interface{}); ok {
			for _, item := range arrayValue {
				if channel, ok := item.(map[string]interface{}); ok {
					// Check if this channel needs migration
					if _, hasJSON := channel["json"]; hasJSON {
						needsMsgFormatMigration = true
						break
					}
					if _, hasJSONFull := channel["json_full"]; hasJSONFull {
						needsMsgFormatMigration = true
						break
					}
					if _, hasMsgFormat := channel["msgformat"]; !hasMsgFormat {
						// No msgformat and no old flags - might need default
						needsMsgFormatMigration = true
						break
					}
				}
			}
			if needsMsgFormatMigration {
				break
			}
		}
	}

	// If no migration needed, return
	if !needsReceiverMigration && !needsMsgFormatMigration && !needsServerArrayMigration {
		return nil
	}

	// Migration needed - show before
	log.Println("=== CONFIG MIGRATION NEEDED ===")
	log.Println("Original configuration:")
	log.Printf("%s", string(jsonContent))
	log.Println("\n" + strings.Repeat("=", 50))

	// Perform receiver migration if needed
	var migratedContent []byte
	if needsReceiverMigration {
		migratedContent, err = MigrateAISCatcherConfig(jsonContent)
		if err != nil {
			log.Printf("Receiver migration failed: %v", err)
			return err
		}
		// Re-parse the migrated content for further processing
		// IMPORTANT: Create a fresh map to avoid retaining old keys
		configMap = make(map[string]interface{})
		if err := json.Unmarshal(migratedContent, &configMap); err != nil {
			log.Printf("Failed to parse migrated content: %v", err)
			return err
		}
		// Re-apply server array migration if needed (since we reparsed configMap)
		if needsServerArrayMigration {
			if serverValue, exists := configMap["server"]; exists {
				if serverObj, isMap := serverValue.(map[string]interface{}); isMap {
					configMap["server"] = []interface{}{serverObj}
				}
			}
		}
	}

	// Server array migration has been applied to configMap
	if needsServerArrayMigration {
		log.Println("Server object converted to array")
	}

	// Perform msgformat migration if needed
	modified := needsServerArrayMigration // Server migration already done
	if needsMsgFormatMigration {
		for _, arrayKey := range channelArrays {
			if arrayValue, ok := configMap[arrayKey].([]interface{}); ok {
				for _, item := range arrayValue {
					if channel, ok := item.(map[string]interface{}); ok {
						if migrateMsgFormat(channel) {
							modified = true
						}
					}
				}
			}
		}

		if modified {
			log.Println("Migrated msgformat in channel arrays (udp, tcp_listener, tcp)")
		}
	}

	// If any migration was performed, marshal the config
	if modified {
		migratedContent, err = json.MarshalIndent(configMap, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal migrated config: %v", err)
			return err
		}
	}

	log.Println("Migrated configuration:")
	log.Printf("%s", string(migratedContent))
	log.Println(strings.Repeat("=", 50))

	// Save migrated config back to file
	if err := os.WriteFile(configJSONFilePath, migratedContent, 0644); err != nil {
		log.Printf("Failed to save migrated config: %v", err)
		return err
	}

	log.Println("Migration completed and saved to file")

	// Update hash to prevent integrity error
	err = updateConfig(func(c *Config) {
		c.ConfigJSONHash = calculate32BitHash(string(migratedContent))
	})
	if err != nil {
		log.Printf("Failed to update config hash: %v", err)
		return err
	}

	return nil
}

func systemActionCancelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Find and stop all update-script services
	cmd := exec.Command("systemctl", "list-units", "--type=service", "update-script-*", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err == nil {
		units := strings.Split(string(output), "\n")
		for _, unit := range units {
			if strings.TrimSpace(unit) != "" {
				unitName := strings.Fields(unit)[0]
				exec.Command("sudo", "systemctl", "stop", unitName).Run()
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func updateScriptLogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	// Tail the logs from update-script.service indefinitely.
	cmd := exec.Command("journalctl", "-f", "-u", "update-script.service", "--no-pager", "--output=json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, "Failed to create stdout pipe: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := cmd.Start(); err != nil {
		http.Error(w, "Failed to start journalctl: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Ensure the command is killed if the client disconnects.
	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		// Send each log line as an SSE message.
		line := parseJournalLine(scanner.Text())
		fmt.Fprintf(w, "data: %s\n\n", strconv.Quote(line))
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading update-script logs: %v", err)
	}
}

func sendSSEMessage(w http.ResponseWriter, flusher http.Flusher, messageType string, content string) {
	msg := map[string]string{
		"type":    messageType,
		"content": content,
	}
	jsonData, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshaling SSE message: %v", err)
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", jsonData)
	flusher.Flush()
}

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
	if cpuinfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
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
	if meminfo, err := os.ReadFile("/proc/meminfo"); err == nil {
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
		"templates/content/mqtt-channels.html",
		"templates/content/output.html",
		"templates/content/sharing-channel.html",
		"templates/content/change-password.html",
		"templates/content/device-setup.html",
		"templates/content/integrity-error.html",
		"templates/content/server-setup.html",
		"templates/content/system.html",
		"templates/content/edit-config-json.html",
		"templates/content/edit-config-cmd.html",
		"templates/content/tcp-servers.html",
		"templates/license.html",
		"templates/webviewer.html",
	)
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]string // sessionID -> username
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]string),
	}
}

func (sm *SessionManager) Create(username string) string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate a secure random session ID
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to less secure if rand fails (unlikely)
		return hashPassword(username + time.Now().String())
	}
	sessionID := hex.EncodeToString(b)

	sm.sessions[sessionID] = username
	return sessionID
}

func (sm *SessionManager) Get(sessionID string) (string, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	user, ok := sm.sessions[sessionID]
	return user, ok
}

func (sm *SessionManager) Delete(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
}

var sessionManager = NewSessionManager()

type Config struct {
	PasswordHash    string `json:"password_hash"`
	Port            string `json:"port"`
	ConfigCmdHash   uint32 `json:"config_cmd_hash"`
	ConfigJSONHash  uint32 `json:"config_json_hash"`
	Docker          bool   `json:"docker"`
	LicenseAccepted bool   `json:"license_accepted"`
}

var (
	config         Config
	integrityError bool
	configMu       sync.RWMutex
)
var execDir string

func getConfig() Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return config
}

func getIntegrityError() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return integrityError
}

func setIntegrityError(val bool) {
	configMu.Lock()
	defer configMu.Unlock()
	integrityError = val
}

func updateConfig(fn func(*Config)) error {
	configMu.Lock()
	defer configMu.Unlock()
	fn(&config)
	return saveControlSettings(config)
}

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
	configMu.Lock()
	defer configMu.Unlock()

	data, err := os.ReadFile(settingsFilePath)
	if os.IsNotExist(err) {
		config = Config{
			PasswordHash:   hashPassword(defaultPassword),
			Port:           "8110",
			ConfigCmdHash:  435605018,
			ConfigJSONHash: 3798370746,
			Docker:         false,
		}
		data, err := json.MarshalIndent(config, "", "    ")
		if err != nil {
			return err
		}
		return os.WriteFile(settingsFilePath, data, 0644)
	} else if err != nil {
		return err
	}

	return json.Unmarshal(data, &config)
}

func saveControlSettings(c Config) error {
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsFilePath, data, 0644)
}

func calculate32BitHash(input string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(input))
	return h.Sum32()
}

// Authentication functions

func licenseHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated to determine if we should show the "Accept" button or just the license
	// For now, we just show the license page.
	// If we wanted to hide the accept button for logged-in users, we could check the cookie here.

	data := map[string]interface{}{
		"CssVersion": cssVersion,
		"Accepted":   getConfig().LicenseAccepted,
	}
	templates.ExecuteTemplate(w, "license.html", data)
}

func acceptLicenseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/license", http.StatusSeeOther)
		return
	}

	err := updateConfig(func(c *Config) {
		c.LicenseAccepted = true
	})
	if err != nil {
		log.Printf("Failed to save license acceptance: %v", err)
		http.Error(w, "Failed to save settings", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func authenticate(username, password string) bool {
	if username != defaultUsername {
		return false
	}
	return hashPassword(password) == getConfig().PasswordHash
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if !getConfig().LicenseAccepted {
		http.Redirect(w, r, "/license", http.StatusSeeOther)
		return
	}

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
		sessionID := sessionManager.Create(username)
		http.SetCookie(w, &http.Cookie{
			Name:  sessionCookieName,
			Value: sessionID,
			Path:  "/",
		})

		if password == defaultPassword && hashPassword(password) == getConfig().PasswordHash {
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
		sessionManager.Delete(cookie.Value)
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
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		user, ok := sessionManager.Get(cookie.Value)
		if !ok || user != defaultUsername {
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

	err := updateConfig(func(c *Config) {
		c.PasswordHash = hashPassword(newPassword)
	})
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

	controlData := Control{
		CssVersion:      cssVersion,
		JsVersion:       jsVersion,
		Title:           "Control Dashboard",
		ContentTemplate: "control",
	}

	err := templates.ExecuteTemplate(w, "layout.html", controlData)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func getServiceStatus() string {
	if getConfig().Docker {
		cmd := exec.Command("/usr/bin/is-running.sh")
		_ = cmd.Run() // We only care about the exit code

		exitCode := cmd.ProcessState.ExitCode()

		if exitCode == 1 {
			return "inactive (stopped)"
		} else if exitCode == 0 {
			return "active (running)"
		} else {
			return "unknown"
		}
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
	if getConfig().Docker {
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

func controlService(action string) error {
	cmd := exec.Command("systemctl", action, "ais-catcher.service")
	return cmd.Run()
}

func getServiceEnabled() (bool, error) {
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

func parseJournalLine(line string) string {
	// Parse JSON output from journalctl
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		// If JSON parsing fails, return the line as-is, but stripped of ANSI codes
		return ansiEscape.ReplaceAllString(line, "")
	}

	// Extract timestamp and message
	timestamp := ""
	if ts, ok := entry["__REALTIME_TIMESTAMP"].(string); ok {
		// Convert microseconds timestamp to readable format
		if usec, err := strconv.ParseInt(ts, 10, 64); err == nil {
			t := time.Unix(usec/1000000, (usec%1000000)*1000)
			timestamp = t.Format("2006-01-02T15:04:05-0700")
		}
	}

	message := ""
	if msg, ok := entry["MESSAGE"].(string); ok {
		message = ansiEscape.ReplaceAllString(msg, "")
	}

	if timestamp != "" && message != "" {
		return timestamp + " " + message
	}

	// Fallback to just the message if timestamp parsing failed
	if message != "" {
		return message
	}

	return ansiEscape.ReplaceAllString(line, "")
}

func readConfigJSON() ([]byte, error) {
	jsonContent, err := os.ReadFile(configJSONFilePath)
	if err != nil {
		log.Printf("Error reading config.json: %v", err)
		return []byte(""), err
	}

	calculatedHash := calculate32BitHash(string(jsonContent))

	if uint32(calculatedHash) != getConfig().ConfigJSONHash {
		fmt.Printf("hash mismatch: config.json content does not match the stored hash (%d != %d)\n", calculatedHash, getConfig().ConfigJSONHash)
		setIntegrityError(true)
	}

	return jsonContent, nil
}

func readConfigCmd() ([]byte, error) {
	cmdContent, err := os.ReadFile(configCmdFilePath)
	if err != nil {
		log.Printf("Error reading config.cmd: %v", err)
		return []byte(""), err
	}

	calculatedHash := calculate32BitHash(string(cmdContent))

	if uint32(calculatedHash) != getConfig().ConfigCmdHash {
		fmt.Printf("hash mismatch: config.cmd content does not match the stored hash (%d != %d)\n", calculatedHash, getConfig().ConfigCmdHash)
		setIntegrityError(true)
	}

	return cmdContent, nil
}

func saveConfigJSON(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %v", err)
	}

	// Validate the JSON data
	var jsonMap map[string]interface{}
	err = json.Unmarshal(body, &jsonMap)
	if err != nil {
		log.Printf("JSON unmarshal error: %v, body: %s", err, string(body))
		return fmt.Errorf("invalid JSON: %v", err)
	}

	// Check that "config" is "aiscatcher" and "version" is 1
	configValue, ok := jsonMap["config"].(string)
	if !ok || configValue != "aiscatcher" {
		log.Printf("Config validation failed: config=%v, ok=%v", configValue, ok)
		return fmt.Errorf("invalid JSON: config value must be 'aiscatcher'")
	}

	versionValue, ok := jsonMap["version"].(float64)
	if !ok || int(versionValue) != 1 {
		log.Printf("Version validation failed: version=%v, ok=%v", versionValue, ok)
		return fmt.Errorf("invalid JSON: version value must be 1")
	}

	hashValue := calculate32BitHash(string(body))
	err = loadControlSettings()
	if err != nil {
		return fmt.Errorf("failed to load control settings: %v", err)
	}

	err = updateConfig(func(c *Config) {
		c.ConfigJSONHash = uint32(hashValue)
	})

	if err != nil {
		return fmt.Errorf("failed to update control settings with new hash: %v", err)
	}

	err = os.WriteFile(configJSONFilePath, body, 0644)
	if err != nil {
		return fmt.Errorf("failed to save config.json: %v", err)
	}

	return nil
}

func recentLogsHandler(w http.ResponseWriter, r *http.Request) {
	// Panic recovery to prevent crashes
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in recentLogsHandler: %v", r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"logs":  []LogMessage{},
				"error": "Internal server error",
			})
		}
	}()

	logSource := r.URL.Query().Get("source")
	if logSource == "" {
		logSource = "ais-catcher"
	}

	linesStr := r.URL.Query().Get("lines")
	lines := 10
	if linesStr != "" {
		if parsedLines, err := strconv.Atoi(linesStr); err == nil && parsedLines > 0 && parsedLines <= 1000 {
			lines = parsedLines
		}
	}

	priority := r.URL.Query().Get("priority")
	if priority == "" {
		priority = "info"
	}

	// Verify journalctl is available
	if _, err := exec.LookPath("journalctl"); err != nil {
		log.Printf("journalctl command not found: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"logs":  []LogMessage{},
			"error": "journalctl not available",
		})
		return
	}

	// Set timeout for command execution
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Build journalctl command with context based on source
	var cmd *exec.Cmd
	switch logSource {
	case "ais-catcher":
		cmd = exec.CommandContext(ctx, "journalctl", "-u", "ais-catcher.service", "-p", priority, "-n", strconv.Itoa(lines), "--no-pager")
	case "control":
		cmd = exec.CommandContext(ctx, "journalctl", "-u", "ais-catcher-control", "-p", priority, "-n", strconv.Itoa(lines), "--no-pager")
	case "system":
		cmd = exec.CommandContext(ctx, "journalctl", "-p", priority, "-n", strconv.Itoa(lines), "--no-pager")
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"logs":  []LogMessage{},
			"error": "Invalid log source",
		})
		return
	}

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("Timeout fetching recent %s logs", logSource)
		} else {
			log.Printf("Error fetching recent %s logs: %v", logSource, err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"logs":  []LogMessage{},
			"error": "Failed to fetch logs",
		})
		return
	}

	lines_output := strings.Split(strings.TrimSpace(string(output)), "\n")
	logs := make([]LogMessage, 0, len(lines_output))
	for _, line := range lines_output {
		if line != "" {
			logs = append(logs, LogMessage{Message: line})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs": logs,
	})
}

func logsStreamHandler(w http.ResponseWriter, r *http.Request) {
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

	// Get log source from query parameter
	logSource := r.URL.Query().Get("source")
	if logSource == "" {
		logSource = "ais-catcher"
	}

	priority := r.URL.Query().Get("priority")
	if priority == "" {
		priority = "info"
	}

	// Create dedicated channel for log streaming using journalctl
	clientChan := make(chan LogMessage, 100)
	defer close(clientChan)

	// Verify journalctl is available
	if _, err := exec.LookPath("journalctl"); err != nil {
		log.Printf("journalctl command not found: %v", err)
		fmt.Fprintf(w, "data: %s\n\n", `{"message":"[ERROR] journalctl not available on this system"}`)
		flusher.Flush()
		return
	}

	// Start log tailing goroutine using journalctl
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic in log streaming: %v", r)
			}
		}()

		var cmd *exec.Cmd
		switch logSource {
		case "ais-catcher":
			cmd = exec.Command("journalctl", "-u", "ais-catcher.service", "-p", priority, "-f", "-n", "0", "--no-pager")
		case "control":
			cmd = exec.Command("journalctl", "-u", "ais-catcher-control", "-p", priority, "-f", "-n", "0", "--no-pager")
		case "system":
			cmd = exec.Command("journalctl", "-p", priority, "-f", "-n", "0", "--no-pager")
		default:
			log.Printf("Invalid log source: %s", logSource)
			return
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("Error creating pipe for %s logs: %v", logSource, err)
			// Try to send error message to client
			select {
			case clientChan <- LogMessage{Message: fmt.Sprintf("[ERROR] Failed to create pipe: %v", err)}:
			default:
			}
			return
		}

		if err := cmd.Start(); err != nil {
			log.Printf("Error starting journalctl for %s logs: %v", logSource, err)
			// Try to send error message to client
			select {
			case clientChan <- LogMessage{Message: fmt.Sprintf("[ERROR] Failed to start journalctl: %v", err)}:
			default:
			}
			return
		}

		// Ensure process is killed when context is done
		go func() {
			<-ctx.Done()
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		}()

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			case clientChan <- LogMessage{Message: scanner.Text()}:
			default:
				// Channel full, skip message to prevent blocking
			}
		}

		// Check for scanner errors
		if err := scanner.Err(); err != nil {
			log.Printf("Scanner error for %s logs: %v", logSource, err)
		}

		// Wait for command to finish
		if err := cmd.Wait(); err != nil {
			// Only log if not killed by context cancellation
			select {
			case <-ctx.Done():
				// Expected termination
			default:
				log.Printf("journalctl command for %s exited with error: %v", logSource, err)
			}
		}
	}()

	// Heartbeat ticker
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Listen for log messages and send them to the client
	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			return
		case <-ticker.C:
			// Send heartbeat
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
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

// makeConfigHandler creates a handler for config pages that follow the same pattern
func makeConfigHandler(title, contentTemplate string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			renderTemplateWithConfig(w, title, contentTemplate)
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
		}
	}
}

func renderTemplateWithConfig(w http.ResponseWriter, title string, contentTemplate string) {
	if true && getIntegrityError() {
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
		"Title":           title,
		"ContentTemplate": contentTemplate,
	}

	err := templates.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func webviewerHandler(w http.ResponseWriter, r *http.Request) {
	port := ""
	hasServer := false

	jsonContent, err := readConfigJSON()
	if err == nil && len(jsonContent) > 0 {
		// Parse as generic map to access server array
		var cfg map[string]interface{}
		if err := json.Unmarshal(jsonContent, &cfg); err == nil {
			// Check if server array exists and has at least one entry
			if servers, ok := cfg["server"].([]interface{}); ok && len(servers) > 0 {
				if firstServer, ok := servers[0].(map[string]interface{}); ok {
					if portVal, ok := firstServer["port"].(float64); ok {
						port = fmt.Sprintf("%.0f", portVal)
						hasServer = true
					} else if portStr, ok := firstServer["port"].(string); ok {
						port = portStr
						hasServer = true
					}
				}
			}
		}
	}

	data := map[string]interface{}{
		"CssVersion": cssVersion,
		"HasServer":  hasServer,
		"port":       port,
	}

	err = templates.ExecuteTemplate(w, "webviewer.html", data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

// makeReadOnlyConfigHandler creates a handler for GET-only config pages
func makeReadOnlyConfigHandler(title, contentTemplate string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			renderTemplateWithConfig(w, title, contentTemplate)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// renderEditorTemplate renders the file editor template with the given data
func renderEditorTemplate(w http.ResponseWriter, title, contentTemplate, content, errMsg, successMsg string) {
	data := map[string]interface{}{
		"CssVersion":      cssVersion,
		"JsVersion":       jsVersion,
		"FileContent":     content,
		"Title":           title,
		"ContentTemplate": contentTemplate,
	}
	if errMsg != "" {
		data["ErrorMessage"] = errMsg
	}
	if successMsg != "" {
		data["SuccessMessage"] = successMsg
	}

	err := templates.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

// sendJSONResponse sends a JSON response with status and optional error
func sendJSONResponse(w http.ResponseWriter, status bool, errorMsg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{"status": status}
	if errorMsg != "" {
		response["error"] = errorMsg
	}
	json.NewEncoder(w).Encode(response)
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

func apiConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		jsonContent, err := readConfigJSON()
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			http.Error(w, "Failed to read config", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonContent)
	} else if r.Method == http.MethodPost {
		// Handle POST request to save JSON data
		err := saveConfigJSON(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Configuration saved successfully."))
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	enabled, _ := getServiceEnabled()
	status := getServiceStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"running": status == "active (running)",
		"uptime":  getServiceUptime(),
		"enabled": enabled,
	})
}

func serviceActionHandler(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendJSONResponse(w, false, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := controlService(action); err != nil {
			log.Println("Service control error:", err)
			sendJSONResponse(w, false, err.Error(), http.StatusInternalServerError)
			return
		}

		sendJSONResponse(w, true, "", http.StatusOK)
	}
}

func editConfigJSONHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		jsonContent, err := readConfigJSON()
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			jsonContent = []byte("")
		}
		renderEditorTemplate(w, "Edit config.json", "edit-config-json", string(jsonContent), "", "")

	} else if r.Method == http.MethodPost {
		newContent := r.FormValue("file_content")

		// Validate JSON
		var jsonMap map[string]interface{}
		if err := json.Unmarshal([]byte(newContent), &jsonMap); err != nil {
			renderEditorTemplate(w, "Edit config.json", "edit-config-json", newContent, "Invalid JSON: "+err.Error(), "")
			return
		}

		// Save file
		if err := os.WriteFile(configJSONFilePath, []byte(newContent), 0644); err != nil {
			renderEditorTemplate(w, "Edit config.json", "edit-config-json", newContent, "Failed to save file: "+err.Error(), "")
			return
		}

		// Update hash
		if err := updateConfig(func(c *Config) { c.ConfigJSONHash = uint32(0) }); err != nil {
			renderEditorTemplate(w, "Edit config.json", "edit-config-json", newContent, "Failed to update control settings: "+err.Error(), "")
			return
		}

		renderEditorTemplate(w, "Edit config.json", "edit-config-json", newContent, "", "Configuration saved successfully.")

	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func editConfigCMDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cmdContent, err := os.ReadFile(configCmdFilePath)
		if err != nil {
			log.Printf("Error reading config.cmd: %v", err)
			cmdContent = []byte("")
		}
		renderEditorTemplate(w, "Edit config.cmd", "edit-config-cmd", string(cmdContent), "", "")

	} else if r.Method == http.MethodPost {
		newContent := r.FormValue("file_content")
		sanitizedContent := sanitizeFileContent(newContent)

		// Save file
		if err := os.WriteFile(configCmdFilePath, []byte(sanitizedContent), 0644); err != nil {
			renderEditorTemplate(w, "Edit config.cmd", "edit-config-cmd", newContent, "Failed to save file: "+err.Error(), "")
			return
		}

		// Update hash
		if err := updateConfig(func(c *Config) { c.ConfigCmdHash = uint32(0) }); err != nil {
			renderEditorTemplate(w, "Edit config.cmd", "edit-config-cmd", newContent, "Failed to update control settings: "+err.Error(), "")
			return
		}

		renderEditorTemplate(w, "Edit config.cmd", "edit-config-cmd", sanitizedContent, "", "Configuration saved successfully.")

	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

type SystemInfoTemplate struct {
	SystemInfo SystemInfo
	MemoryGB   float64
	CssVersion string
	JsVersion  string
}

func systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	collectSystemInfo()

	memoryGB := float64(systemInfo.TotalMemory) / 1073741824.0

	err := templates.ExecuteTemplate(w, "layout.html", map[string]interface{}{
		"CssVersion":      cssVersion,
		"JsVersion":       jsVersion,
		"Title":           "System Information",
		"ContentTemplate": "system",
		"SystemInfo":      systemInfo,
		"MemoryGB":        memoryGB,
	})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func main() {

	resetHashes := flag.Bool("overwrite-hashes", false, "Reset configuration file hashes")
	flag.Parse()

	err := initPaths()
	if err != nil {
		log.Fatal("Failed to initialize paths:", err)
	}

	if *resetHashes {
		err := loadControlSettings()
		if err != nil {
			log.Fatal("Failed to load control settings:", err)
		}

		jsonContent, err := os.ReadFile(configJSONFilePath)
		if err != nil {
			log.Fatal("Failed to read config.json:", err)
		}
		config.ConfigJSONHash = calculate32BitHash(string(jsonContent))

		// Calculate and set hash for config.cmd
		cmdContent, err := os.ReadFile(configCmdFilePath)
		if err != nil {
			log.Fatal("Failed to read config.cmd:", err)
		}
		config.ConfigCmdHash = calculate32BitHash(string(cmdContent))

		err = saveControlSettings(config)
		if err != nil {
			log.Fatal("Failed to save control settings:", err)
		}

		fmt.Printf("Configuration hashes have been reset successfully:\n")
		fmt.Printf("config.json hash: %d\n", config.ConfigJSONHash)
		fmt.Printf("config.cmd hash: %d\n", config.ConfigCmdHash)
		os.Exit(0)
	}

	collectSystemInfo()

	if err := checkTailCommand(); err != nil {
		log.Fatalf("Required command not found: %v", err)
	}

	err = loadControlSettings()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	if err := migrateConfigAtStartup(); err != nil {
		log.Printf("Config migration error: %v", err)
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
	jsVersion = getFileVersion(staticFSys, "js/config-manager.js")

	_, err = readConfigJSON()
	if err != nil {
		log.Fatal("Failed to read config.json:", err)
	}

	_, err = readConfigCmd()
	if err != nil {
		log.Fatal("Failed to read config.cmd:", err)
	}

	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		http.StripPrefix("/static/", http.FileServer(http.FS(staticFSys))).ServeHTTP(w, r)
	})

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/license", licenseHandler)
	http.HandleFunc("/api/accept-license", acceptLicenseHandler)
	http.HandleFunc("/api/config", authMiddleware(apiConfigHandler))
	http.HandleFunc("/sharing", authMiddleware(makeConfigHandler("Community Sharing", "sharing-channel")))
	http.HandleFunc("/udp", authMiddleware(makeConfigHandler("UDP Channels", "udp-channels")))
	http.HandleFunc("/tcp", authMiddleware(makeConfigHandler("TCP Channels", "tcp-channels")))
	http.HandleFunc("/http", authMiddleware(makeConfigHandler("HTTP Channels", "http-channels")))
	http.HandleFunc("/mqtt", authMiddleware(makeConfigHandler("MQTT Channels", "mqtt-channels")))
	http.HandleFunc("/output", authMiddleware(makeReadOnlyConfigHandler("Output Configuration", "output")))
	http.HandleFunc("/control", authMiddleware(controlHandler))
	http.HandleFunc("/change-password", authMiddleware(changePasswordHandler))
	http.HandleFunc("/api/start", authMiddleware(serviceActionHandler("start")))
	http.HandleFunc("/api/stop", authMiddleware(serviceActionHandler("stop")))
	http.HandleFunc("/api/restart", authMiddleware(serviceActionHandler("restart")))
	http.HandleFunc("/api/enable", authMiddleware(serviceActionHandler("enable")))
	http.HandleFunc("/api/disable", authMiddleware(serviceActionHandler("disable")))
	http.HandleFunc("/api/recent-logs", authMiddleware(recentLogsHandler))
	http.HandleFunc("/logs-stream", authMiddleware(logsStreamHandler))
	http.HandleFunc("/status", authMiddleware(statusHandler))
	http.HandleFunc("/device", authMiddleware(makeConfigHandler("Device Configuration", "device-setup")))
	http.HandleFunc("/server", authMiddleware(makeConfigHandler("Webviewer Setup", "server-setup")))
	http.HandleFunc("/webviewer", authMiddleware(webviewerHandler))
	http.HandleFunc("/logout", authMiddleware(logoutHandler))
	http.HandleFunc("/device-list", authMiddleware(deviceListHandler))
	http.HandleFunc("/serial-list", authMiddleware(serialListHandler))
	http.HandleFunc("/editjson", authMiddleware(editConfigJSONHandler))
	http.HandleFunc("/editcmd", authMiddleware(editConfigCMDHandler))
	http.HandleFunc("/system", authMiddleware(systemInfoHandler))
	http.HandleFunc("/system-action-progress", authMiddleware(systemActionProgressHandler))
	http.HandleFunc("/system-action-status", authMiddleware(systemActionStatusHandler))
	http.HandleFunc("/system-action-cancel", authMiddleware(systemActionCancelHandler))
	http.HandleFunc("/update-script-logs", authMiddleware(updateScriptLogsHandler))
	http.HandleFunc("/tcp-servers", authMiddleware(makeConfigHandler("TCP Servers", "tcp-servers")))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !getConfig().LicenseAccepted {
			http.Redirect(w, r, "/license", http.StatusSeeOther)
			return
		}
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil {
			if user, ok := sessionManager.Get(cookie.Value); ok && user == defaultUsername {
				http.Redirect(w, r, "/control", http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	addr := ":" + getConfig().Port
	log.Printf("Server started at %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
