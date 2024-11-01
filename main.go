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


func Seq(start, end int) []int {
	if end < start {
		return []int{}
	}
	s := make([]int, end-start+1)
	for i := range s {
		s[i] = start + i
	}
	return s
}

func init() {
	funcMap := template.FuncMap{
		"dynamicTemplate": func(name string, data interface{}) (template.HTML, error) {
			var buf strings.Builder
			err := templates.ExecuteTemplate(&buf, name, data)
			return template.HTML(buf.String()), err
		},
		"seq": Seq,
	}

	templates = template.New("").Funcs(funcMap)

	var err error
	templates, err = templates.ParseFS(templatesFS,
		"templates/layout.html",
		"templates/login.html",
		"templates/navigation.html",
		"templates/content/control.html",
		"templates/content/udp-channels.html",
		"templates/content/tcp-channels.html",
		"templates/content/sharing-channel.html",
		"templates/content/change-password.html",
		"templates/content/input-selection.html",
		"templates/content/device-setup.html",
		"templates/content/integrity-error.html",
		"templates/content/server-setup.html",
		"templates/content/webviewer.html",
	)
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
}

var sessions = map[string]string{}

type Config struct {
	PasswordHash   string `json:"password_hash"`
	Port           string `json:"port"`
	ConfigCmdHash  int    `json:"config_cmd_hash"`
	ConfigJSONHash int    `json:"config_json_hash"`
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
			ConfigCmdHash:  1,
			ConfigJSONHash: 1,
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

	config.ConfigJSONHash = int(hashValue)
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
		templates.ExecuteTemplate(w, "login.html", nil)
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

		if false && password == defaultPassword && hashPassword(password) == config.PasswordHash {
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/control", http.StatusSeeOther)
		}
	} else {
		templates.ExecuteTemplate(w, "login.html", "Invalid credentials")
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

	cmd := exec.Command("journalctl", "-u", "ais-catcher.service", "-n", fmt.Sprintf("%d", lines), "--no-pager", "--output=short-iso")
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

	if int(calculatedHash) != config.ConfigJSONHash {
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

	if int(calculatedHash) != config.ConfigCmdHash {
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

	config.ConfigJSONHash = int(hashValue)
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
	cmd := exec.Command("journalctl", "-u", "ais-catcher.service", "-n", "0", "-f", "--no-pager", "--output=short-iso")
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

	if false /*configIntegrityError*/ {
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
		"port": port,
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
		"status": status,
		"uptime": uptime,
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

func main() {

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
