package main

import (
	"bufio"
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
)

var (
	cssVersion string
	jsVersion  string
)

var configIntegrityError = false

var templates *template.Template

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
	// Create a FuncMap with both "dynamicTemplate" and "seq"
	funcMap := template.FuncMap{
		"dynamicTemplate": func(name string, data interface{}) (template.HTML, error) {
			var buf strings.Builder
			err := templates.ExecuteTemplate(&buf, name, data)
			return template.HTML(buf.String()), err
		},
		"seq": Seq,
	}

	// Create a new template with the function map
	templates = template.New("").Funcs(funcMap)

	// Parse all templates including partials and content from the embedded filesystem
	var err error
	templates, err = templates.ParseFS(templatesFS,
		"templates/layout.html",
		"templates/login.html",
		"templates/header.html",
		"templates/navigation.html",
		"templates/footer.html",
		"templates/modal/modal.html",
		"templates/content/control.html",
		"templates/content/udp-channels.html",
		"templates/content/tcp-channels.html",
		"templates/content/sharing-channel.html",
		"templates/content/change-password.html",
		"templates/content/input-selection.html",
		"templates/content/device-setup.html",
		"templates/content/integrity-error.html",
	)

	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
}

var sessions = map[string]string{}

// Configuration struct
type Config struct {
	PasswordHash   string `json:"password_hash"`
	Port           string `json:"port"`
	ConfigCmdHash  int    `json:"config_cmd_hash"`
	ConfigJSONHash int    `json:"config_json_hash"`
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

func getServiceStartTime() (time.Time, error) {
	cmd := exec.Command("systemctl", "show", "ais-catcher.service", "--property=ActiveEnterTimestamp")
	output, err := cmd.Output()
	if err != nil {
		return time.Time{}, err
	}
	line := strings.TrimSpace(string(output))
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("Unexpected output from systemctl")
	}
	timestamp := parts[1]
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", timestamp)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
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
			// Prompt to change default password
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
			"message":         "Password do not match",
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

	// Validate that the output is valid JSON
	var jsonData interface{}
	err = json.Unmarshal(stdout, &jsonData)
	if err != nil {
		log.Printf("Invalid JSON from AIS-catcher: %v", err)
		http.Error(w, "Invalid JSON data received from AIS-catcher", http.StatusInternalServerError)
		return
	}

	// Set the Content-Type header to application/json
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(stdout)
}

func controlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Gather necessary data
	status := getServiceStatus()
	uptime := getServiceUptime()
	logs := getServiceLogs(50) // Adjust the number of logs as needed
	enabled, err := getServiceEnabled()
	if err != nil {
		enabled = false // Default to false if there's an error
		log.Println("Error fetching service enabled status:", err)
	}

	data := map[string]interface{}{
		"CssVersion":      cssVersion,
		"JsVersion":       jsVersion,
		"Title":           "Control Dashboard",
		"Status":          status,
		"Uptime":          uptime,
		"Logs":            logs,
		"ServiceEnabled":  enabled,
		"ContentTemplate": "control",
	}

	err = templates.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

// Function to get the service status
func getServiceStatus() string {
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

// Function to get the service uptime
func getServiceUptime() string {
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

// Helper function to format duration
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

// Function to get recent service logs
func getServiceLogs(lines int) []string {
	cmd := exec.Command("journalctl", "-u", "ais-catcher.service", "-n", fmt.Sprintf("%d", lines), "--no-pager", "--output=short-iso")
	output, err := cmd.Output()

	if err != nil {
		return []string{"Unable to retrieve logs"}
	}

	logLines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return logLines
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

	http.Redirect(w, r, "/control", http.StatusSeeOther)
}

func sanitizeFileContent(content string) string {
	// Implement any necessary sanitization here
	// For example, remove unwanted characters or validate JSON if editing config.json
	return content
}

func logsStreamHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Create a context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Ensure the journalctl process is terminated when the context is canceled
	cmd := exec.CommandContext(ctx, "journalctl", "-u", "ais-catcher.service", "-f", "--no-pager", "--output=short-iso")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, "Failed to get stdout", http.StatusInternalServerError)
		return
	}

	if err := cmd.Start(); err != nil {
		http.Error(w, "Failed to start journalctl", http.StatusInternalServerError)
		return
	}

	defer cmd.Wait()

	// Handle client disconnection
	notify := w.(http.CloseNotifier).CloseNotify()
	go func() {
		<-notify
		cancel()
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		sanitizedLine := sanitizeLogLine(line)
		fmt.Fprintf(w, "data: %s\n\n", sanitizedLine)
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Println("Error reading logs:", err)
	}
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
	fmt.Println("Saved control.json content:")

	configJSON, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		fmt.Printf("Failed to marshal config to JSON: %v\n", err)
		return nil
	}
	fmt.Println(string(configJSON))

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
		log.Printf("Received GET request for /udp")
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

func main() {
	err := initPaths()
	if err != nil {
		log.Fatal("Failed to initialize paths:", err)
	}

	err = loadControlSettings()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	staticFSys, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal("Failed to create sub filesystem:", err)
	}

	cssVersion = getFileVersion(staticFSys, "css/styles.css")
	jsVersion = getFileVersion(staticFSys, "js/scripts.js")

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
	http.HandleFunc("/sharing", authMiddleware(sharingChannelsHandler))
	http.HandleFunc("/udp", authMiddleware(udpChannelsHandler))
	http.HandleFunc("/tcp", authMiddleware(tcpChannelsHandler))
	http.HandleFunc("/control", authMiddleware(controlHandler))
	http.HandleFunc("/change-password", authMiddleware(changePasswordHandler))
	http.HandleFunc("/service", authMiddleware(serviceHandler))
	http.HandleFunc("/logs-stream", authMiddleware(logsStreamHandler))
	http.HandleFunc("/device", authMiddleware(deviceSetupHandler))
	http.HandleFunc("/input", authMiddleware(inputSelectionHandler))
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
