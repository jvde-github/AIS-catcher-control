package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	defaultUsername   = "admin"
	defaultPassword   = "admin"
	sessionCookieName = "session_id"
	// Set the configJSONFilePath and settingsFilePath directly to the absolute paths
	configJSONFilePath = "/etc/AIS-catcher/config.json"
	settingsFilePath   = "/etc/AIS-catcher/control.json"
)

var (
	cssVersion string
	jsVersion  string
)

var templates *template.Template

func init() {
	funcMap := template.FuncMap{
		"dynamicTemplate": func(name string, data interface{}) (template.HTML, error) {
			var buf strings.Builder
			err := templates.ExecuteTemplate(&buf, name, data)
			return template.HTML(buf.String()), err
		},
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
	)

	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
}

var sessions = map[string]string{} // session_id -> username

// Configuration struct
type Config struct {
	PasswordHash   string `json:"password_hash"`
	Port           string `json:"port"`
	ServiceEnabled bool   `json:"service_enabled"`
}

// Global variable to hold the configuration
var config Config

// Paths
var execDir string

func initPaths() error {
	// Determine the directory of the executable (not strictly necessary now)
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

func loadConfig() error {
	data, err := ioutil.ReadFile(settingsFilePath)
	if os.IsNotExist(err) {
		// If settings file doesn't exist, create it with default values
		config = Config{
			PasswordHash:   hashPassword(defaultPassword),
			Port:           "8110",
			ServiceEnabled: true, // default to enabled
		}
		return saveConfig()
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

func saveConfig() error {
	data, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}
	// Write to settingsFilePath with appropriate permissions
	return ioutil.WriteFile(settingsFilePath, data, 0644)
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
	err := saveConfig()
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

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	status := getServiceStatus()
	uptime := getServiceUptime()
	logs := getServiceLogs(50) // Get the last 10 log entries
	enabled, err := getServiceEnabled()
	if err != nil {
		enabled = false // default to false if error occurs
		log.Println("Error fetching service enabled status:", err)
	}

	data := map[string]interface{}{
		"Status":         status,
		"Uptime":         uptime,
		"Logs":           logs,
		"ServiceEnabled": enabled,
	}
	templates.ExecuteTemplate(w, "dashboard.html", data)
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

	// Update the config if action is enable or disable
	if action == "enable" {
		config.ServiceEnabled = true
		saveConfig()
	} else if action == "disable" {
		config.ServiceEnabled = false
		saveConfig()
	}

	http.Redirect(w, r, "/control", http.StatusSeeOther)
}

func editorHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /editor")
		log.Printf("Attempting to read config.json from: %s", configJSONFilePath)

		// Read config.json
		jsonContent, err := ioutil.ReadFile(configJSONFilePath)
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			jsonContent = []byte("")
		} else {
			log.Printf("Successfully read config.json")
		}

		data := map[string]interface{}{
			"JsonContent": string(jsonContent),
		}
		templates.ExecuteTemplate(w, "editor.html", data)
		return
	}

	if r.Method == http.MethodPost {
		// Parse form data
		err := r.ParseForm()
		if err != nil {
			templates.ExecuteTemplate(w, "editor.html", map[string]interface{}{
				"Error": "Failed to parse form data: " + err.Error(),
			})
			return
		}

		// Get content for config.json
		jsonContent := r.FormValue("json_content")

		// Validate and save config.json
		err = validateAndSaveConfigJSON([]byte(jsonContent))
		if err != nil {
			log.Printf("Error saving config.json: %v", err)
			data := map[string]interface{}{
				"JsonContent": jsonContent,
				"Error":       err.Error(),
			}
			templates.ExecuteTemplate(w, "editor.html", data)
			return
		}

		// Optionally, reload the configuration if necessary
		err = loadConfig()
		if err != nil {
			log.Printf("Error reloading configuration: %v", err)
			data := map[string]interface{}{
				"JsonContent": jsonContent,
				"Error":       "Configuration saved, but failed to reload: " + err.Error(),
			}
			templates.ExecuteTemplate(w, "editor.html", data)
			return
		}

		data := map[string]interface{}{
			"JsonContent": jsonContent,
			"Message":     "Configuration saved successfully. Please restart the service.",
		}
		templates.ExecuteTemplate(w, "editor.html", data)
	}
}

// Helper function to sanitize file content
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

func validateAndSaveConfigJSON(data []byte) error {
	// Validate the JSON data
	var jsonMap map[string]interface{}
	err := json.Unmarshal(data, &jsonMap)
	if err != nil {
		return fmt.Errorf("Invalid JSON: %v", err)
	}

	// Check that "config" is "aiscatcher" and "version" is 1
	configValue, ok := jsonMap["config"].(string)
	if !ok || configValue != "aiscatcher" {
		return fmt.Errorf("Invalid JSON: config value must be 'aiscatcher'")
	}

	versionValue, ok := jsonMap["version"].(float64)
	if !ok || versionValue != 1 {
		return fmt.Errorf("Invalid JSON: version value must be 1")
	}

	// Save the JSON data to the config.json file
	err = ioutil.WriteFile(configJSONFilePath, data, 0644)
	if err != nil {
		return fmt.Errorf("Failed to save config.json: %v", err)
	}

	return nil
}

// --- New Function: saveUDPChannelsConfig ---
func saveUDPChannelsConfig(w http.ResponseWriter, r *http.Request) error {
	// Read the JSON data from the request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("Failed to read request body: %v", err)
	}

	// Validate and save the JSON data
	err = validateAndSaveConfigJSON(body)
	if err != nil {
		return err
	}

	return nil
}

// --- Updated udpChannelsHandler ---
func udpChannelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /udp")

		// Read config.json
		jsonContent, err := ioutil.ReadFile(configJSONFilePath)
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			jsonContent = []byte("")
		}

		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"JsonContent":     string(jsonContent),
			"Title":           "UDP Channels",
			"ContentTemplate": "udp-channels", // Specify the content template
		}

		errt := templates.ExecuteTemplate(w, "layout.html", data)
		if errt != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", errt)
		}
	} else if r.Method == http.MethodPost {
		// Handle POST request to save JSON data
		err := saveUDPChannelsConfig(w, r)
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

		// Read config.json
		jsonContent, err := ioutil.ReadFile(configJSONFilePath)
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			jsonContent = []byte("")
		}

		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"JsonContent":     string(jsonContent),
			"Title":           "Community Sharing Settings",
			"ContentTemplate": "sharing-channel",
		}

		errt := templates.ExecuteTemplate(w, "layout.html", data)
		if errt != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", errt)
		}
	} else if r.Method == http.MethodPost {
		// Handle POST request to save JSON data
		err := saveUDPChannelsConfig(w, r)
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

func inputSelectionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /input")

		// Read config.json
		jsonContent, err := ioutil.ReadFile(configJSONFilePath)
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			jsonContent = []byte("")
		}

		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"JsonContent":     string(jsonContent),
			"Title":           "Community Sharing Settings",
			"ContentTemplate": "input-selection",
		}

		errt := templates.ExecuteTemplate(w, "layout.html", data)
		if errt != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", errt)
		}
	} else if r.Method == http.MethodPost {
		// Handle POST request to save JSON data
		err := saveUDPChannelsConfig(w, r)
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
func tcpChannelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		log.Printf("Received GET request for /tcp")

		// Read config.json
		jsonContent, err := ioutil.ReadFile(configJSONFilePath)
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			jsonContent = []byte("")
		}

		data := map[string]interface{}{
			"CssVersion":      cssVersion,
			"JsVersion":       jsVersion,
			"JsonContent":     string(jsonContent),
			"Title":           "TCP Channels",
			"ContentTemplate": "tcp-channels", // Specify the content template
		}

		errt := templates.ExecuteTemplate(w, "layout.html", data)
		if errt != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", errt)
		}
	} else if r.Method == http.MethodPost {
		// Handle POST request to save JSON data
		err := saveUDPChannelsConfig(w, r)
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
	return hex.EncodeToString(hash[:])[:8] // Use first 8 characters for brevity
}

func main() {
	// Initialize paths
	err := initPaths()
	if err != nil {
		log.Fatal("Failed to initialize paths:", err)
	}

	// Load configuration
	err = loadConfig()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Set up the embedded static file system
	staticFSys, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal("Failed to create sub filesystem:", err)
	}

	// Compute version hashes for CSS and JS files
	cssVersion = getFileVersion(staticFSys, "css/styles.css")
	jsVersion = getFileVersion(staticFSys, "js/scripts.js")

	// Handlers
	//http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFSys))))

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
	http.HandleFunc("/dashboard", authMiddleware(dashboardHandler))
	http.HandleFunc("/service", authMiddleware(serviceHandler))
	http.HandleFunc("/editor", authMiddleware(editorHandler))
	http.HandleFunc("/logs-stream", authMiddleware(logsStreamHandler))
	http.HandleFunc("/input", authMiddleware(inputSelectionHandler))
	http.HandleFunc("/logout", authMiddleware(logoutHandler))
	http.HandleFunc("/device-list", authMiddleware(deviceListHandler))

	// Redirect root to login or dashboard based on authentication
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil && sessions[cookie.Value] == defaultUsername {
			http.Redirect(w, r, "/control", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
	})

	// Start the server on the configured port
	addr := ":" + config.Port
	log.Printf("Server started at %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
