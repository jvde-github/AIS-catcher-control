package main

import (
    "bufio"
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
    // Set the configCmdFilePath and settingsFilePath directly to the absolute paths
    configCmdFilePath = "/etc/AIS-catcher/config.cmd"
    settingsFilePath  = "/etc/AIS-catcher/control.json"
)

var templates *template.Template
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
    log.Printf("Config CMD file path: %s", configCmdFilePath)

    return nil
}

func initTemplates() {
    tmplFS, err := fs.Sub(templatesFS, "templates")
    if err != nil {
        log.Fatal(err)
    }
    templates = template.Must(template.ParseFS(tmplFS, "*.html"))
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

        if password == defaultPassword && hashPassword(password) == config.PasswordHash {
            // Prompt to change default password
            http.Redirect(w, r, "/change-password", http.StatusSeeOther)
        } else {
            http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
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
        templates.ExecuteTemplate(w, "change_password.html", nil)
        return
    }

    newPassword := r.FormValue("new_password")
    confirmPassword := r.FormValue("confirm_password")

    if newPassword != confirmPassword {
        templates.ExecuteTemplate(w, "change_password.html", "Passwords do not match")
        return
    }

    config.PasswordHash = hashPassword(newPassword)
    err := saveConfig()
    if err != nil {
        templates.ExecuteTemplate(w, "change_password.html", "Failed to save new password")
        return
    }

    // Update session
    cookie, _ := r.Cookie(sessionCookieName)
    sessions[cookie.Value] = defaultUsername

    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
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
        "start":    true,
        "stop":     true,
        "restart":  true,
        "enable":   true,
        "disable":  true,
    }

    if !validActions[action] {
        http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
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

    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func editorHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        log.Printf("Received GET request for /editor")
        log.Printf("Attempting to read config.cmd from: %s", configCmdFilePath)

        content, err := ioutil.ReadFile(configCmdFilePath)
        if err != nil {
            log.Printf("Error reading config.cmd: %v", err)
            data := map[string]interface{}{
                "Content": "",
                "Error":   "Error reading configuration file: " + err.Error(),
            }
            templates.ExecuteTemplate(w, "editor.html", data)
            return
        } else {
            log.Printf("Successfully read config.cmd")
        }

        data := map[string]interface{}{
            "Content": string(content),
        }
        templates.ExecuteTemplate(w, "editor.html", data)
        return
    }

    if r.Method == http.MethodPost {
        content := r.FormValue("content")

        // Remove all \r characters to avoid carriage returns
        content = strings.ReplaceAll(content, "\r", "")

        // Save the updated command line
        err := ioutil.WriteFile(configCmdFilePath, []byte(content), 0644)
        if err != nil {
            log.Printf("Error writing to config.cmd: %v", err)
            data := map[string]interface{}{
                "Content": content,
                "Error":   "Failed to save configuration file: " + err.Error(),
            }
            templates.ExecuteTemplate(w, "editor.html", data)
            return
        }

        data := map[string]interface{}{
            "Content": content,
            "Message": "Configuration saved. Please restart the service.",
        }
        templates.ExecuteTemplate(w, "editor.html", data)
    }
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

    cmd := exec.Command("journalctl", "-u", "ais-catcher.service", "-f", "--no-pager", "--output=short-iso")
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

    scanner := bufio.NewScanner(stdout)
    for scanner.Scan() {
        line := scanner.Text()
        sanitizedLine := sanitizeLogLine(line)
        //  log.Printf("Streaming log: %s", sanitizedLine) // Debugging log
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

    initTemplates()

    // Set up the embedded static file system
    staticFSys, err := fs.Sub(staticFS, "static")
    if err != nil {
        log.Fatal("Failed to create sub filesystem:", err)
    }

    // Serve static files with correct MIME types
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFSys))))

    // Register handlers
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/change-password", authMiddleware(changePasswordHandler))
    http.HandleFunc("/dashboard", authMiddleware(dashboardHandler))
    http.HandleFunc("/service", authMiddleware(serviceHandler))
    http.HandleFunc("/editor", authMiddleware(editorHandler))
    http.HandleFunc("/logs-stream", authMiddleware(logsStreamHandler))
    http.HandleFunc("/logout", authMiddleware(logoutHandler))

    // Redirect root to login or dashboard based on authentication
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie(sessionCookieName)
        if err == nil && sessions[cookie.Value] == defaultUsername {
            http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
        } else {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
        }
    })

    // Start the server on the configured port
    addr := ":" + config.Port
    log.Printf("Server started at %s\n", addr)
    log.Fatal(http.ListenAndServe(addr, nil))
}
