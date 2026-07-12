package main

import (
	"bufio"
	"bytes"
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
	"net"
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

	"golang.org/x/crypto/bcrypt"
)

var (
	buildVersion = "dev"     // Human-readable version: git describe --tags --always
	buildCommit  = "unknown" // Raw short commit hash: git rev-parse --short HEAD
	ansiEscape   = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
)

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
	aisBinaryPath      = "/usr/bin/AIS-catcher"
)

var (
	cssVersion string
	jsVersion  string
)

type SystemInfo struct {
	AISCatcherVersion      string    `json:"ais_catcher_version"`      // Full version string
	AISCatcherVersionCode  int       `json:"ais_catcher_version_code"` // Numeric version
	AISCatcherDescribe     string    `json:"ais_catcher_describe"`     // Detailed version info
	AISCatcherCommit       string    `json:"ais_catcher_commit"`       // Git commit hash
	AISCatcherBuildType    string    `json:"ais_catcher_build_type"`   // Build type: "Source", "Build #123", etc.
	AISCatcherAvailable    bool      `json:"ais_catcher_available"`    // Is AIS-catcher installed
	OS                     string    `json:"os"`                       // Operating system
	Architecture           string    `json:"architecture"`             // CPU architecture
	CPUInfo                string    `json:"cpu_info"`                 // CPU information
	TotalMemory            uint64    `json:"total_memory"`             // Total system memory
	KernelVersion          string    `json:"kernel_version"`           // Linux kernel version
	ServiceStatus          string    `json:"service_status"`           // systemd service status
	ManagedMode            bool      `json:"managed_mode"`             // service is self-configured (-E flag in ExecStart)
	ManagedPort            string    `json:"managed_port"`             // port of AIS-catcher's own web UI in managed mode
	BuildVersion           string    `json:"build_version"`            // Git version/build info
	ProcessID              int32     `json:"process_id"`
	ProcessMemoryUsage     float64   `json:"process_memory_usage"` // in MB
	ProcessCPUUsage        float64   `json:"process_cpu_usage"`    // percentage
	ProcessStartTime       time.Time `json:"process_start_time"`
	ProcessThreadCount     int32     `json:"process_thread_count"`
	SystemCPUUsage         float64   `json:"system_cpu_usage"`         // percentage
	SystemMemoryUsage      float64   `json:"system_memory_usage"`      // percentage
	LatestVersion          string    `json:"latest_version"`           // Latest release from GitHub
	LatestVersionTag       string    `json:"latest_version_tag"`       // Latest tag
	LatestCommit           string    `json:"latest_commit"`            // Latest commit hash from GitHub
	UpdateAvailable        bool      `json:"update_available"`         // Whether update is available
	LastChecked            time.Time `json:"last_checked"`             // Last time we checked GitHub
	ControlLatestCommit    string    `json:"control_latest_commit"`    // Latest Control panel commit from GitHub
	ControlUpdateAvailable bool      `json:"control_update_available"` // Whether Control panel update is available
	ControlLastChecked     time.Time `json:"control_last_checked"`     // Last time we checked Control repo

	UnitProps map[string]string `json:"-"` // raw systemctl show values backing /status
}

type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
}

type CachedSystemInfo struct {
	sync.RWMutex
	info      SystemInfo
	lastFetch time.Time
	cacheTTL  time.Duration
}

var templates *template.Template

var cachedSysInfo = &CachedSystemInfo{
	cacheTTL: 3 * time.Second, // Cache for 3 seconds
}

type LogMessage struct {
	Source   string `json:"source"`
	Message  string `json:"message"`
	Priority int    `json:"priority"`
	Time     string `json:"time"`
}

// journalEntry is used to unmarshal a single line from journalctl -o json
type journalEntry struct {
	Message           json.RawMessage `json:"MESSAGE"`
	Priority          string          `json:"PRIORITY"`
	RealtimeTimestamp string          `json:"__REALTIME_TIMESTAMP"`
}

// parseJournalJSON parses one JSON line from journalctl -o json.
// MESSAGE may be a plain string or an array of byte values (binary syslog).
// PRIORITY is a syslog level string "0"–"7" (0=emerg … 7=debug).
// __REALTIME_TIMESTAMP is microseconds since Unix epoch as a string.
func parseJournalJSON(line string) (msg string, priority int, ts string, ok bool) {
	priority = 6 // default: info
	var entry journalEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return "", 0, "", false
	}
	if p, err := strconv.Atoi(entry.Priority); err == nil && p >= 0 && p <= 7 {
		priority = p
	}
	if entry.RealtimeTimestamp != "" {
		if usec, err := strconv.ParseInt(entry.RealtimeTimestamp, 10, 64); err == nil {
			t := time.Unix(usec/1_000_000, (usec%1_000_000)*1000)
			ts = t.Local().Format("15:04:05")
		}
	}
	if len(entry.Message) > 0 {
		switch entry.Message[0] {
		case '"':
			var s string
			if err := json.Unmarshal(entry.Message, &s); err == nil {
				msg = s
			}
		case '[':
			var nums []int
			if err := json.Unmarshal(entry.Message, &nums); err == nil {
				b := make([]byte, len(nums))
				for i, n := range nums {
					b[i] = byte(n)
				}
				msg = string(b)
			}
		}
	}
	return msg, priority, ts, true
}

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

func rebootPendingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	out, _ := runCmd(3*time.Second, "systemctl", "is-active", "ais-catcher-reboot.service") // non-zero exit for inactive

	state := strings.TrimSpace(string(out))
	pending := state == "active" || state == "activating"
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pending": pending,
		"message": "Reboot-on-failure watchdog triggered",
	})
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

// aisInstallCmd downloads and runs the AIS-catcher installer with the given flags.
func aisInstallCmd(flags string) string {
	return "curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher/main/scripts/aiscatcher-install | bash -s --" + flags
}

const controlInstallCmd = "curl -fsSL https://raw.githubusercontent.com/jvde-github/AIS-catcher-control/main/install_ais_catcher_control.sh | bash"

func getActionScript(action string) (string, bool) {
	switch action {
	case "system-update":
		return `echo "Starting system update..." && apt-get update -y && echo "System update completed"`, false

	case "ais-update-prebuilt":
		return `echo "Starting AIS-catcher prebuilt update..." && ` +
			aisInstallCmd(" -p"+managedInstallFlag()) +
			` && echo "AIS-catcher installation completed"`, false

	case "ais-update-source":
		return `echo "Starting AIS-catcher source update..." && ` +
			aisInstallCmd(managedInstallFlag()) +
			` && echo "AIS-catcher installation completed"`, false

	case "control-update":
		return `echo "Starting AIS-catcher Control update..." && ` +
			controlInstallCmd +
			` && echo "AIS-catcher Control installation completed"`, true

	case "control-restart":
		return `echo "Restarting AIS-catcher Control..." && systemctl restart ais-catcher-control && echo "AIS-catcher Control restarted successfully"`, true

	case "system-reboot":
		return `echo "Initiating system reboot..." && reboot`, true

	case "system-halt":
		return `echo "Initiating system shutdown..." && shutdown`, true

	case "update-all":
		return `echo "Step 1: Installing AIS-catcher..." && ` +
			aisInstallCmd(" -p"+managedInstallFlag()) +
			` && echo "Step 2: Installing AIS-catcher Control..." && ` +
			controlInstallCmd +
			` && echo "Full system update completed"`, true

	case "update-all-reboot":
		return `echo "Step 1: Installing AIS-catcher..." && ` +
			aisInstallCmd(" -p"+managedInstallFlag()) +
			` && echo "Step 2: Installing AIS-catcher Control..." && ` +
			controlInstallCmd +
			` && echo "Full system update completed" && echo "Step 3: Preparing for reboot..." && reboot`, true

	case "switch-managed":
		return `echo "Switching AIS-catcher to managed mode..." && ` +
			aisInstallCmd(" -p -M") +
			` && echo "AIS-catcher now runs in managed mode"`, true

	case "switch-unmanaged":
		return `echo "Switching AIS-catcher to unmanaged (classic) mode..." && ` +
			aisInstallCmd(" -p") +
			` && echo "AIS-catcher now runs in unmanaged mode"`, true

	case "shutdown-cancel":
		return `echo "Cancelling pending shutdown/reboot..." && shutdown -c ; systemctl stop ais-catcher-reboot.service ; echo "Scheduled shutdown/reboot has been cancelled"`, false
	}

	return "", false
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

	// Attach-only: actions are started via POST /api/system-action-start (CSRF).
	globalActionState.Lock()
	if globalActionState.IsRunning {
		if requestedAction != "" && requestedAction != globalActionState.ActionName {
			globalActionState.Unlock()
			sendSSEMessage(w, flusher, "error", "Another system action is already in progress")
			return
		}
	} else {
		// Not running: replay the recent result for late-connecting clients.
		if globalActionState.Result != nil {
			result := *globalActionState.Result
			history := make([]string, len(globalActionState.Logs))
			copy(history, globalActionState.Logs)
			globalActionState.Unlock()
			for _, line := range history {
				sendSSEMessage(w, flusher, "output", line)
			}
			sendSSEMessage(w, flusher, result.Type, result.Content)
		} else {
			globalActionState.Unlock()
			if requestedAction != "" {
				sendSSEMessage(w, flusher, "error", "No such action in progress")
			}
		}
		return
	}

	msgChan := make(chan SSEMessage, 100)
	globalActionState.Subscribers[msgChan] = true

	history := make([]string, len(globalActionState.Logs))
	copy(history, globalActionState.Logs)

	globalActionState.Unlock()

	for _, log := range history {
		sendSSEMessage(w, flusher, "output", log)
	}

	ctx := r.Context()

	for {
		select {
		case msg, ok := <-msgChan:
			if !ok {
				return // channel closed by broadcastResult (terminal message may have been dropped)
			}
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

// systemActionStartHandler is POST-only: GET requests can be triggered
// cross-site with cookies attached (CSRF).
func systemActionStartHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONResponse(w, false, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Action == "" {
		sendJSONResponse(w, false, "Invalid request body", http.StatusBadRequest)
		return
	}

	script, reload := getActionScript(req.Action)
	if script == "" {
		sendJSONResponse(w, false, "Invalid action", http.StatusBadRequest)
		return
	}

	globalActionState.Lock()
	if globalActionState.IsRunning {
		running := globalActionState.ActionName
		globalActionState.Unlock()
		if running == req.Action {
			// already running — report success so the client attaches
			sendJSONResponse(w, true, "", http.StatusOK)
			return
		}
		sendJSONResponse(w, false, "Another system action is already in progress", http.StatusConflict)
		return
	}
	globalActionState.IsRunning = true
	globalActionState.ActionName = req.Action
	globalActionState.Logs = []string{}
	globalActionState.Result = nil
	globalActionState.Unlock()

	go runSystemAction(req.Action, script, reload)
	sendJSONResponse(w, true, "", http.StatusOK)
}

func runSystemAction(actionName, script string, reload bool) {
	unitName := fmt.Sprintf("ais-update-%d", time.Now().UnixNano())

	useSystemd := false
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		useSystemd = true
	}

	var runCmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if useSystemd {
		runCmd = exec.CommandContext(ctx, "systemd-run",
			"--unit="+unitName,
			"--property=Type=oneshot",
			"--pipe",
			"--collect",
			"/bin/bash", "-c", script)
	} else {
		runCmd = exec.CommandContext(ctx, "/bin/bash", "-c", script)
	}

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

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
		delete(globalActionState.Subscribers, ch)
		close(ch) // unblocks reader even if the message above was dropped
	}

	// Refresh system info after action completes to get updated version
	go func() {
		time.Sleep(2 * time.Second) // Brief delay to ensure any file writes are complete
		cachedSysInfo.Lock()
		cachedSysInfo.lastFetch = time.Time{} // Force cache refresh
		cachedSysInfo.Unlock()
		// synchronous, so the update flags clear right after a successful update
		getCachedSystemInfo()
		checkLatestVersion()
		checkControlLatestVersion()
	}()
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

// runCmd runs a command with a timeout and returns its stdout.
func runCmd(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// userHZ is the kernel USER_HZ used for /proc tick values; fixed at 100 on Linux.
const userHZ = 100

// scanForAISCatcherPID finds AIS-catcher running outside the service.
func scanForAISCatcherPID() int32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		pid, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err == nil && strings.TrimSpace(string(comm)) == "AIS-catcher" {
			return int32(pid)
		}
	}
	return 0
}

func readProcStatus(pid int32) (rssKB uint64, threads int32, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				rssKB, _ = strconv.ParseUint(f[0], 10, 64)
			}
		} else if v, ok := strings.CutPrefix(line, "Threads:"); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 32)
			threads = int32(n)
		}
	}
	return rssKB, threads, nil
}

func readProcStat(pid int32) (utime, stime, starttime uint64, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, 0, err
	}
	// comm may contain spaces and parens; fields start after the last ')'
	s := string(data)
	idx := strings.LastIndexByte(s, ')')
	if idx < 0 {
		return 0, 0, 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(s[idx+1:])
	if len(fields) < 20 {
		return 0, 0, 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	utime, _ = strconv.ParseUint(fields[11], 10, 64)
	stime, _ = strconv.ParseUint(fields[12], 10, 64)
	starttime, _ = strconv.ParseUint(fields[19], 10, 64)
	return utime, stime, starttime, nil
}

var cachedBootTime int64

func bootTime() (int64, error) {
	if cachedBootTime != 0 {
		return cachedBootTime, nil
	}
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			bt, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err == nil {
				cachedBootTime = bt
			}
			return bt, err
		}
	}
	return 0, fmt.Errorf("btime not found in /proc/stat")
}

// prevProcCPU, prevSysCPU and lastAISBinaryModTime are only touched from
// collectSystemInfo, which runs under the cachedSysInfo write lock.
var lastAISBinaryModTime time.Time

var prevProcCPU struct {
	pid   int32
	ticks uint64
	at    time.Time
}

func processCPUPercent(pid int32, ticks uint64, started time.Time) float64 {
	now := time.Now()
	prevPid, prevTicks, prevAt := prevProcCPU.pid, prevProcCPU.ticks, prevProcCPU.at
	prevProcCPU.pid, prevProcCPU.ticks, prevProcCPU.at = pid, ticks, now

	if prevPid == pid && ticks >= prevTicks {
		if elapsed := now.Sub(prevAt).Seconds(); elapsed > 0 {
			return float64(ticks-prevTicks) / userHZ / elapsed * 100
		}
	}
	// first sample: average since process start
	if life := now.Sub(started).Seconds(); !started.IsZero() && life > 0 {
		return float64(ticks) / userHZ / life * 100
	}
	return 0
}

var prevSysCPU struct {
	busy  uint64
	total uint64
}

func systemCPUPercent() (float64, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, false
	}
	var total, idle uint64
	for i, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return 0, false
		}
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	busy := total - idle
	prevBusy, prevTotal := prevSysCPU.busy, prevSysCPU.total
	prevSysCPU.busy, prevSysCPU.total = busy, total

	if prevTotal > 0 && total > prevTotal && busy >= prevBusy {
		return float64(busy-prevBusy) / float64(total-prevTotal) * 100, true
	}
	if total > 0 {
		return float64(busy) / float64(total) * 100, true // first sample: since boot
	}
	return 0, false
}

// getCachedSystemInfo returns cached system info or fetches new if expired
func getCachedSystemInfo() SystemInfo {
	cachedSysInfo.RLock()
	if time.Since(cachedSysInfo.lastFetch) < cachedSysInfo.cacheTTL {
		info := cachedSysInfo.info
		cachedSysInfo.RUnlock()
		return info
	}
	cachedSysInfo.RUnlock()

	cachedSysInfo.Lock()
	defer cachedSysInfo.Unlock()

	// Double-check after acquiring write lock
	if time.Since(cachedSysInfo.lastFetch) < cachedSysInfo.cacheTTL {
		return cachedSysInfo.info
	}

	cachedSysInfo.info = collectSystemInfo(cachedSysInfo.info)
	cachedSysInfo.lastFetch = time.Now()
	return cachedSysInfo.info
}

// unitShowProps is the single systemctl query per cache refresh; it feeds the
// cached system info, the managed-mode cache and the /status endpoint.
var unitShowProps = []string{"ActiveState", "SubState", "UnitFileState", "ActiveEnterTimestamp",
	"MainPID", "ExecStart", "NRestarts", "StartLimitBurst", "StartLimitIntervalUSec",
	"OnFailure", "Result", "ExecMainStatus", "RestartUSec", "Restart"}

func queryUnitProps() map[string]string {
	args := []string{"show", "ais-catcher.service"}
	for _, p := range unitShowProps {
		args = append(args, "--property="+p)
	}
	props := map[string]string{}
	if out, err := runCmd(5*time.Second, "systemctl", args...); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if idx := strings.IndexByte(line, '='); idx > 0 {
				props[line[:idx]] = line[idx+1:]
			}
		}
	}
	return props
}

func serviceStatusFromProps(props map[string]string) string {
	switch props["ActiveState"] {
	case "active":
		return "active (running)"
	case "inactive":
		return "inactive (stopped)"
	case "":
		return "unknown"
	}
	return props["ActiveState"]
}

func collectSystemInfo(prev SystemInfo) SystemInfo {
	info := prev // seeds LastChecked, LatestVersion, etc. from cache

	info.BuildVersion = buildVersion

	props := queryUnitProps()
	info.UnitProps = props

	pid := int32(0)
	if v, err := strconv.ParseInt(props["MainPID"], 10, 32); err == nil && v > 0 {
		pid = int32(v)
	} else {
		pid = scanForAISCatcherPID()
	}

	if pid > 0 {
		info.ProcessID = pid
		if rssKB, threads, err := readProcStatus(pid); err == nil {
			info.ProcessMemoryUsage = float64(rssKB) / 1024 // Convert to MB
			info.ProcessThreadCount = threads
		}
		if utime, stime, starttime, err := readProcStat(pid); err == nil {
			if bt, err := bootTime(); err == nil {
				info.ProcessStartTime = time.Unix(bt+int64(starttime/userHZ), 0)
			}
			info.ProcessCPUUsage = processCPUPercent(pid, utime+stime, info.ProcessStartTime)
		}
	} else {
		info.ProcessID = 0
		info.ProcessMemoryUsage = 0
		info.ProcessCPUUsage = 0
		info.ProcessStartTime = time.Time{}
		info.ProcessThreadCount = 0
	}

	if pct, ok := systemCPUPercent(); ok {
		info.SystemCPUUsage = pct
	}

	info.OS = runtime.GOOS
	info.Architecture = runtime.GOARCH

	// Skip version check if system action is running or service is down
	// to avoid collision with binary file being updated
	globalActionState.Lock()
	isActionRunning := globalActionState.IsRunning
	globalActionState.Unlock()

	serviceStatus := serviceStatusFromProps(props)
	info.ServiceStatus = serviceStatus

	// derive managed mode from the same query and refresh its cache
	managed, bind := parseExecStartManaged(props["ExecStart"])
	setManagedModeCache(managed, bind)
	info.ManagedMode = managed
	info.ManagedPort = managedPort()

	skipVersionCheck := isActionRunning && serviceStatus != "active (running)"

	// only exec the binary when it changed on disk (or was never parsed)
	fi, statErr := os.Stat(aisBinaryPath)
	binaryChanged := statErr != nil || !fi.ModTime().Equal(lastAISBinaryModTime) || info.AISCatcherVersion == ""

	if !skipVersionCheck && binaryChanged {
		if statErr == nil {
			lastAISBinaryModTime = fi.ModTime()
		} else {
			lastAISBinaryModTime = time.Time{}
		}

		// reset so values from a previously installed binary never survive a reinstall
		info.AISCatcherCommit = ""
		info.AISCatcherBuildType = ""

		// runs while the system-info cache lock is held, so it must be bounded
		vCtx, vCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer vCancel()
		cmd := exec.CommandContext(vCtx, aisBinaryPath, "-h", "JSON")
		output, err := cmd.CombinedOutput()
		firstLine := strings.Split(string(output), "\n")[0]

		if err != nil {
			log.Printf("Command error: %v", err)
			if exitErr, ok := err.(*exec.ExitError); ok {
				log.Printf("Exit error code: %d", exitErr.ExitCode())
				info.AISCatcherAvailable = true
				info.AISCatcherVersion = "v0.60 or earlier"
				info.AISCatcherVersionCode = -1
				info.AISCatcherDescribe = "Version before JSON support"
			} else {
				info.AISCatcherAvailable = false
				info.AISCatcherVersion = "not installed"
				info.AISCatcherVersionCode = 0
				info.AISCatcherDescribe = "Not found in system"
			}
		} else {
			var jsonOutput map[string]interface{}
			if err := json.Unmarshal([]byte(firstLine), &jsonOutput); err != nil {
				log.Printf("JSON unmarshal error: %v", err)
				info.AISCatcherAvailable = true
				info.AISCatcherVersion = "unknown"
				info.AISCatcherVersionCode = -1
				info.AISCatcherDescribe = "Invalid JSON output"
			} else {
				info.AISCatcherAvailable = true
				if v, ok := jsonOutput["version"].(string); ok {
					info.AISCatcherVersion = v
				} else {
					info.AISCatcherVersion = "unknown"
				}
				if vc, ok := jsonOutput["version_code"].(float64); ok {
					info.AISCatcherVersionCode = int(vc)
				} else {
					info.AISCatcherVersionCode = -1
				}
				if d, ok := jsonOutput["version_describe"].(string); ok {
					info.AISCatcherDescribe = d
				} else {
					info.AISCatcherDescribe = ""
				}

				if commitVal, ok := jsonOutput["commit"]; ok {
					if commitStr, ok := commitVal.(string); ok && commitStr != "" {
						info.AISCatcherCommit = commitStr
						if len(commitStr) > 7 {
							info.AISCatcherCommit = commitStr[:7]
						}
					}
				}

				// Parse build type from describe string (format: v0.66-0-g1abc2def or v0.66-123-g1abc2def)
				describe := info.AISCatcherDescribe
				if idx := strings.LastIndex(describe, "-g"); idx != -1 {
					if info.AISCatcherCommit == "" {
						info.AISCatcherCommit = describe[idx+2:] // Extract hash after '-g'
						if len(info.AISCatcherCommit) > 7 {
							info.AISCatcherCommit = info.AISCatcherCommit[:7]
						}
					}

					parts := strings.Split(describe[:idx], "-")
					if len(parts) >= 2 {
						buildNum := parts[len(parts)-1]
						if buildNum == "0" {
							info.AISCatcherBuildType = "Release"
						} else {
							info.AISCatcherBuildType = "package (#" + buildNum + ")"
						}
					}
				} else if info.AISCatcherCommit == "" {
					// If no -g in describe and no commit from JSON, it's a release build
					info.AISCatcherBuildType = "Release"
				}
			}
		}
	}

	// static hardware info: collect once
	if info.CPUInfo == "" {
		if cpuinfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(cpuinfo)))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "model name") {
					info.CPUInfo = strings.TrimSpace(strings.Split(line, ":")[1])
					break
				}
			}
		}
	}

	if info.TotalMemory == 0 {
		if meminfo, err := os.ReadFile("/proc/meminfo"); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(meminfo)))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "MemTotal:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						if mem, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
							info.TotalMemory = mem * 1024 // Convert from KB to bytes
						}
					}
					break
				}
			}
		}
	}

	if info.KernelVersion == "" {
		if kernel, err := runCmd(5*time.Second, "uname", "-r"); err == nil {
			info.KernelVersion = strings.TrimSpace(string(kernel))
		}
	}

	// GitHub checks run async so a slow/unreachable API never blocks page load
	if time.Since(info.LastChecked) > 10*time.Minute {
		info.LastChecked = time.Now() // pre-stamp to prevent thundering herd
		go checkLatestVersion()
	}
	if time.Since(info.ControlLastChecked) > 10*time.Minute {
		info.ControlLastChecked = time.Now() // pre-stamp to prevent thundering herd
		go checkControlLatestVersion()
	}

	// Recompute UpdateAvailable using the freshly-read installed commit and the
	// cached GitHub latest commit. This makes the flag accurate immediately
	// after a manual binary update, without waiting for the next GitHub re-check.
	recomputeUpdateAvailable(&info)

	return info
}

// recomputeUpdateAvailable derives UpdateAvailable from the installed binary
// and the cached GitHub data on info.
func recomputeUpdateAvailable(info *SystemInfo) {
	if !info.AISCatcherAvailable {
		info.UpdateAvailable = false
		return
	}
	latestTag := strings.TrimPrefix(info.LatestVersionTag, "v")
	if latestTag == "" && info.LatestCommit == "" {
		return // no GitHub data yet — keep the previous value
	}
	currentVersion := ""
	if parts := strings.Fields(info.AISCatcherVersion); len(parts) > 0 {
		currentVersion = strings.TrimPrefix(parts[0], "v")
	}
	if strings.EqualFold(info.AISCatcherBuildType, "source") {
		info.UpdateAvailable = info.LatestCommit != "" &&
			info.AISCatcherCommit != "" && info.AISCatcherCommit != info.LatestCommit
		return
	}
	info.UpdateAvailable = (latestTag != "" && currentVersion != latestTag) ||
		(currentVersion == latestTag &&
			info.AISCatcherCommit != "" && info.LatestCommit != "" &&
			info.AISCatcherCommit != info.LatestCommit)
}

// githubGet fetches and decodes a GitHub API response; false on any failure.
func githubGet(url string, v interface{}) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("GitHub request failed (%s): %v", url, err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("GitHub API returned status %d for %s", resp.StatusCode, url)
		return false
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		log.Printf("Failed to decode GitHub response (%s): %v", url, err)
		return false
	}
	return true
}

// githubLatestCommit returns the short HEAD commit of a repo's main branch.
func githubLatestCommit(repo string) string {
	var commit struct {
		SHA string `json:"sha"`
	}
	if githubGet("https://api.github.com/repos/"+repo+"/commits/main", &commit) && len(commit.SHA) >= 7 {
		return commit.SHA[:7]
	}
	return ""
}

// checkLatestVersion fetches the latest AIS-catcher release and main commit
// from GitHub, updating only the GitHub-related cache fields.
func checkLatestVersion() {
	var release GitHubRelease
	if !githubGet("https://api.github.com/repos/jvde-github/AIS-catcher/releases/latest", &release) {
		return
	}
	latestCommit := githubLatestCommit("jvde-github/AIS-catcher")

	cachedSysInfo.Lock()
	defer cachedSysInfo.Unlock()

	info := &cachedSysInfo.info
	info.LatestVersion = release.Name
	info.LatestVersionTag = release.TagName
	info.LastChecked = time.Now()
	if latestCommit != "" {
		info.LatestCommit = latestCommit
	}
	recomputeUpdateAvailable(info)
}

// checkControlLatestVersion fetches the latest Control panel commit from GitHub.
func checkControlLatestVersion() {
	latestCommit := githubLatestCommit("jvde-github/AIS-catcher-control")
	if latestCommit == "" {
		return
	}

	cachedSysInfo.Lock()
	defer cachedSysInfo.Unlock()

	info := &cachedSysInfo.info
	info.ControlLatestCommit = latestCommit
	info.ControlLastChecked = time.Now()

	if buildCommit != "unknown" && buildCommit != "" {
		current := buildCommit
		if len(current) > 7 {
			current = current[:7]
		}
		info.ControlUpdateAvailable = current != info.ControlLatestCommit
	}
}

func init() {
	funcMap := template.FuncMap{
		"dynamicTemplate": func(name string, data interface{}) (template.HTML, error) {
			var buf strings.Builder
			err := templates.ExecuteTemplate(&buf, name, data)
			return template.HTML(buf.String()), err
		},
		"managedMode": func() bool {
			managed, _ := getManagedMode()
			return managed
		},
		"managedPort": managedPort,
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
		"templates/content/edit-config-json.html",
		"templates/content/edit-config-cmd.html",
		"templates/content/tcp-servers.html",
		"templates/content/general-settings.html",
		"templates/content/zones.html",
		"templates/license.html",
		"templates/webviewer.html",
	)
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
}

const sessionTTL = 24 * time.Hour

type sessionEntry struct {
	username  string
	createdAt time.Time
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry
}

func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]sessionEntry),
	}
	go sm.cleanupLoop()
	return sm
}

func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		sm.mu.Lock()
		for id, e := range sm.sessions {
			if now.Sub(e.createdAt) > sessionTTL {
				delete(sm.sessions, id)
			}
		}
		sm.mu.Unlock()
	}
}

func (sm *SessionManager) Create(username string) string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure means the OS entropy pool is broken — do not
		// proceed with a predictable session token on an admin panel.
		log.Fatalf("crypto/rand failure, cannot generate secure session ID: %v", err)
	}
	sessionID := hex.EncodeToString(b)

	sm.sessions[sessionID] = sessionEntry{username: username, createdAt: time.Now()}
	return sessionID
}

func (sm *SessionManager) Get(sessionID string) (string, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	e, ok := sm.sessions[sessionID]
	if !ok || time.Since(e.createdAt) > sessionTTL {
		return "", false
	}
	return e.username, true
}

func (sm *SessionManager) Delete(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
}

func (sm *SessionManager) DeleteAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions = make(map[string]sessionEntry)
}

var sessionManager = NewSessionManager()

// loginLimiter applies a per-IP lockout after repeated failed logins.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string]*loginFailure
}

type loginFailure struct {
	count       int
	lockedUntil time.Time
	lastFailure time.Time
}

var loginAttempts = &loginLimiter{failures: make(map[string]*loginFailure)}

func (l *loginLimiter) blocked(ip string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f, ok := l.failures[ip]; ok {
		if remaining := time.Until(f.lockedUntil); remaining > 0 {
			return remaining, true
		}
	}
	return 0, false
}

func (l *loginLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, f := range l.failures {
		if now.Sub(f.lastFailure) > time.Hour {
			delete(l.failures, k)
		}
	}
	f := l.failures[ip]
	if f == nil {
		f = &loginFailure{}
		l.failures[ip] = f
	}
	f.count++
	f.lastFailure = now
	if f.count >= 5 {
		f.lockedUntil = now.Add(time.Duration(f.count-4) * 30 * time.Second)
	}
}

func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}

// clientIP deliberately ignores X-Forwarded-For, which is spoofable without a
// trusted proxy in front.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type Config struct {
	PasswordHash    string `json:"password_hash"`
	Port            string `json:"port"`
	ConfigCmdHash   uint32 `json:"config_cmd_hash"`
	ConfigJSONHash  uint32 `json:"config_json_hash"`
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

	log.Printf("Version: %s", buildVersion)
	log.Printf("Executable directory: %s", execDir)
	log.Printf("Settings file path: %s", settingsFilePath)
	log.Printf("Config JSON file path: %s", configJSONFilePath)

	return nil
}

func hashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	return string(hash)
}

// legacyHashPassword verifies hashes written by earlier versions; they are
// upgraded to bcrypt on first login.
func legacyHashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

func verifyPassword(password, stored string) bool {
	if strings.HasPrefix(stored, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	}
	return legacyHashPassword(password) == stored
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
		}
		data, err := json.MarshalIndent(config, "", "    ")
		if err != nil {
			return err
		}
		return writeFileAtomic(settingsFilePath, data, 0644)
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
	return writeFileAtomic(settingsFilePath, data, 0644)
}

func calculate32BitHash(input string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(input))
	return h.Sum32()
}

// configFileMu serializes read-modify-write cycles on config.json.
var configFileMu sync.Mutex

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func licenseHandler(w http.ResponseWriter, r *http.Request) {

	data := map[string]interface{}{
		"CssVersion": cssVersion,
		"Accepted":   getConfig().LicenseAccepted,
	}
	renderTemplate(w, "license.html", data)
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

// Login is password-only; defaultUsername survives purely as the internal
// marker stored in sessions.
func authenticate(password string) bool {
	return verifyPassword(password, getConfig().PasswordHash)
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	user, ok := sessionManager.Get(cookie.Value)
	return ok && user == defaultUsername
}

func renderLoginPage(w http.ResponseWriter, message string) {
	renderTemplate(w, "login.html", map[string]interface{}{
		"CssVersion": cssVersion,
		"JsVersion":  jsVersion,
		"message":    message,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if !getConfig().LicenseAccepted {
		http.Redirect(w, r, "/license", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		renderLoginPage(w, "")
		return
	}

	password := r.FormValue("password")

	ip := clientIP(r)
	if wait, blocked := loginAttempts.blocked(ip); blocked {
		renderLoginPage(w, fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", int(wait.Seconds())+1))
		return
	}

	if !authenticate(password) {
		loginAttempts.recordFailure(ip)
		renderLoginPage(w, "Invalid credentials")
		return
	}

	loginAttempts.recordSuccess(ip)

	// upgrade legacy SHA-256 hash to bcrypt
	if !strings.HasPrefix(getConfig().PasswordHash, "$2") {
		if err := updateConfig(func(c *Config) { c.PasswordHash = hashPassword(password) }); err != nil {
			log.Printf("Failed to upgrade password hash to bcrypt: %v", err)
		}
	}

	setSessionCookie(w, r, sessionManager.Create(defaultUsername), 0)

	if password == defaultPassword {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/control", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		sessionManager.Delete(cookie.Value)
		setSessionCookie(w, r, "", -1)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func renderChangePassword(w http.ResponseWriter, message string) {
	renderTemplate(w, "layout.html", map[string]interface{}{
		"CssVersion":      cssVersion,
		"JsVersion":       jsVersion,
		"Title":           "Change Password",
		"ContentTemplate": "change-password",
		"message":         message,
	})
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderChangePassword(w, "")
		return
	}

	newPassword := r.FormValue("new_password")
	if newPassword != r.FormValue("confirm_password") {
		renderChangePassword(w, "Passwords do not match")
		return
	}

	if err := updateConfig(func(c *Config) { c.PasswordHash = hashPassword(newPassword) }); err != nil {
		renderChangePassword(w, "Failed to save new password")
		return
	}

	sessionManager.DeleteAll()
	setSessionCookie(w, r, sessionManager.Create(defaultUsername), 0)

	http.Redirect(w, r, "/control", http.StatusSeeOther)
}

func deviceListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/AIS-catcher", "-l", "JSON", "ON")
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

	if entries, err := os.ReadDir("/dev/serial/by-id"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				devices = append(devices, "/dev/serial/by-id/"+entry.Name())
			}
		}
	}

	if entries, err := os.ReadDir("/dev"); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, "ttyUSB") || // USB serial devices
				strings.HasPrefix(name, "ttyACM") || // USB ACM devices
				strings.HasPrefix(name, "ttyAMA") || // Raspberry Pi and others
				strings.HasPrefix(name, "ttyS") || // Standard serial ports
				name == "serial0" || name == "serial1" { // Raspberry Pi aliases

				devicePath := "/dev/" + name
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

	// Return immediately with cached data (even if stale) for fast page load
	cachedSysInfo.RLock()
	sysInfo := cachedSysInfo.info
	stale := time.Since(cachedSysInfo.lastFetch) > cachedSysInfo.cacheTTL
	cachedSysInfo.RUnlock()
	if sysInfo.BuildVersion == "" {
		// First time, need to collect at least basic info
		sysInfo = getCachedSystemInfo()
	} else if stale {
		go getCachedSystemInfo()
	}

	renderTemplate(w, "layout.html", map[string]interface{}{
		"CssVersion":      cssVersion,
		"JsVersion":       jsVersion,
		"Title":           "Control Dashboard",
		"ContentTemplate": "control",
		"SystemInfo":      sysInfo,
		"MemoryGB":        float64(sysInfo.TotalMemory) / 1073741824.0,
	})
}

// managedModeCache caches the detected run mode briefly so page renders and
// action starts don't each shell out to systemctl, while a mode change made
// by an install/update is still picked up within seconds.
var managedModeCache = struct {
	sync.Mutex
	managed bool
	bind    string
	checked time.Time
}{}

// getManagedMode reports whether ais-catcher.service runs in managed mode
// (AIS-catcher configures itself, started with -E <config> <bind>) and the
// bind address following the flag, e.g. "0.0.0.0:8118". In unmanaged mode
// the service reads config.json/config.cmd owned by this panel.
func getManagedMode() (bool, string) {
	managedModeCache.Lock()
	defer managedModeCache.Unlock()
	if time.Since(managedModeCache.checked) < 3*time.Second {
		return managedModeCache.managed, managedModeCache.bind
	}

	managed := false
	bind := ""
	out, err := runCmd(5*time.Second, "systemctl", "show", "ais-catcher.service", "--property=ExecStart")
	if err == nil {
		managed, bind = parseExecStartManaged(string(out))
	}

	managedModeCache.managed = managed
	managedModeCache.bind = bind
	managedModeCache.checked = time.Now()
	return managed, bind
}

func setManagedModeCache(managed bool, bind string) {
	managedModeCache.Lock()
	defer managedModeCache.Unlock()
	managedModeCache.managed = managed
	managedModeCache.bind = bind
	managedModeCache.checked = time.Now()
}

// parseExecStartManaged extracts the run mode from systemctl's ExecStart
// property, e.g.:
// ExecStart={ path=/usr/bin/AIS-catcher ; argv[]=/usr/bin/AIS-catcher -E /etc/AIS-catcher/aiscatcher.json 0.0.0.0:8118 ; ignore_errors=no ; ... }
func parseExecStartManaged(line string) (managed bool, bind string) {
	if idx := strings.Index(line, "argv[]="); idx >= 0 {
		args := line[idx+len("argv[]="):]
		if end := strings.Index(args, " ; "); end >= 0 {
			args = args[:end]
		}
		fields := strings.Fields(args)
		for i, f := range fields {
			if f == "-E" {
				managed = true
				// argv is: ... -E <config file> <bind address>
				if i+2 < len(fields) {
					bind = fields[i+2]
				}
				break
			}
		}
	}
	if managed && bind == "" {
		bind = "0.0.0.0:8118"
	}
	return managed, bind
}

// managedPort returns the TCP port of AIS-catcher's own web UI in managed
// mode, or "" when unmanaged.
func managedPort() string {
	managed, bind := getManagedMode()
	if !managed {
		return ""
	}
	if idx := strings.LastIndex(bind, ":"); idx >= 0 {
		return bind[idx+1:]
	}
	return bind
}

// managedInstallFlag preserves the current run mode across reinstalls: an
// update of a managed system must pass -M or the installer would rewrite the
// unit back to unmanaged.
func managedInstallFlag() string {
	if managed, _ := getManagedMode(); managed {
		return " -M"
	}
	return ""
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

func cancelPendingShutdown() {
	runCmd(10*time.Second, "shutdown", "-c")
	runCmd(10*time.Second, "systemctl", "stop", "ais-catcher-reboot.service")
}

func controlService(action string) error {
	cancelPendingShutdown()
	// Reset failed state and NRestarts counter before any action
	runCmd(10*time.Second, "systemctl", "reset-failed", "ais-catcher.service")
	_, err := runCmd(30*time.Second, "systemctl", action, "ais-catcher.service")
	return err
}

// journalctlArgs builds the argument list for reading logs from the given
// source; returns nil for an unknown source.
func journalctlArgs(source, priority string, extra ...string) []string {
	var args []string
	switch source {
	case "ais-catcher":
		args = append(args, "-u", "ais-catcher.service")
	case "control":
		args = append(args, "-u", "ais-catcher-control")
	case "system":
	default:
		return nil
	}
	args = append(args, "-p", priority, "--no-pager", "-o", "json", "--output-fields=MESSAGE,PRIORITY,__REALTIME_TIMESTAMP")
	return append(args, extra...)
}

// readConfigFile reads a panel-owned config file and flags an integrity error
// when its content no longer matches the stored hash.
func readConfigFile(path string, storedHash uint32) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Error reading %s: %v", path, err)
		return []byte(""), err
	}

	calculatedHash := calculate32BitHash(string(content))
	if calculatedHash != storedHash {
		log.Printf("hash mismatch: %s content does not match the stored hash (%d != %d)", path, calculatedHash, storedHash)
		setIntegrityError(true)
	} else {
		setIntegrityError(false)
	}

	return content, nil
}

func readConfigJSON() ([]byte, error) {
	return readConfigFile(configJSONFilePath, getConfig().ConfigJSONHash)
}

func readConfigCmd() ([]byte, error) {
	return readConfigFile(configCmdFilePath, getConfig().ConfigCmdHash)
}

// writeConfigWithHash writes a config file atomically and records its hash so
// the integrity check accepts the new content; the hash must only ever
// describe content that made it to disk.
func writeConfigWithHash(path string, content []byte, set func(*Config, uint32)) error {
	if err := writeFileAtomic(path, content, 0644); err != nil {
		return fmt.Errorf("failed to save %s: %v", filepath.Base(path), err)
	}
	hash := calculate32BitHash(string(content))
	if err := updateConfig(func(c *Config) { set(c, hash) }); err != nil {
		return fmt.Errorf("failed to update control settings with new hash: %v", err)
	}
	return nil
}

func setJSONHash(c *Config, h uint32) { c.ConfigJSONHash = h }
func setCmdHash(c *Config, h uint32)  { c.ConfigCmdHash = h }

func saveConfigJSON(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read request body: %v", err)
	}

	var jsonMap map[string]interface{}
	err = json.Unmarshal(body, &jsonMap)
	if err != nil {
		log.Printf("JSON unmarshal error: %v, body: %s", err, string(body))
		return fmt.Errorf("invalid JSON: %v", err)
	}

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

	configFileMu.Lock()
	defer configFileMu.Unlock()

	return writeConfigWithHash(configJSONFilePath, body, setJSONHash)
}

// writeLogsJSON writes the recent-logs response; errMsg is included when set.
func writeLogsJSON(w http.ResponseWriter, logs []LogMessage, errMsg string) {
	w.Header().Set("Content-Type", "application/json")
	if logs == nil {
		logs = []LogMessage{}
	}
	resp := map[string]interface{}{"logs": logs}
	if errMsg != "" {
		resp["error"] = errMsg
	}
	json.NewEncoder(w).Encode(resp)
}

func recentLogsHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in recentLogsHandler: %v", r)
			w.WriteHeader(http.StatusInternalServerError)
			writeLogsJSON(w, nil, "Internal server error")
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

	if _, err := exec.LookPath("journalctl"); err != nil {
		log.Printf("journalctl command not found: %v", err)
		writeLogsJSON(w, nil, "journalctl not available")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	args := journalctlArgs(logSource, priority, "-n", strconv.Itoa(lines))
	if args == nil {
		writeLogsJSON(w, nil, "Invalid log source")
		return
	}

	output, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("Timeout fetching recent %s logs", logSource)
		} else {
			log.Printf("Error fetching recent %s logs: %v", logSource, err)
		}
		writeLogsJSON(w, nil, "Failed to fetch logs")
		return
	}

	lines_output := strings.Split(strings.TrimSpace(string(output)), "\n")
	logs := make([]LogMessage, 0, len(lines_output))
	for _, line := range lines_output {
		if line == "" {
			continue
		}
		if msg, prio, ts, ok := parseJournalJSON(line); ok {
			logs = append(logs, LogMessage{Message: msg, Priority: prio, Time: ts})
		} else {
			logs = append(logs, LogMessage{Message: line, Priority: 6})
		}
	}

	writeLogsJSON(w, logs, "")
}

func logsStreamHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	logSource := r.URL.Query().Get("source")
	if logSource == "" {
		logSource = "ais-catcher"
	}

	priority := r.URL.Query().Get("priority")
	if priority == "" {
		priority = "info"
	}

	// Create dedicated channel for log streaming using journalctl.
	// Do NOT close this channel here — the background goroutine writes to it
	// and closing a channel from the reader side causes a panic on write.
	// The channel is garbage-collected once both sides exit.
	clientChan := make(chan LogMessage, 100)

	if _, err := exec.LookPath("journalctl"); err != nil {
		log.Printf("journalctl command not found: %v", err)
		fmt.Fprintf(w, "data: %s\n\n", `{"message":"[ERROR] journalctl not available on this system"}`)
		flusher.Flush()
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic in log streaming: %v", r)
			}
		}()

		args := journalctlArgs(logSource, priority, "-f", "-n", "0")
		if args == nil {
			log.Printf("Invalid log source: %s", logSource)
			return
		}
		cmd := exec.Command("journalctl", args...)

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("Error creating pipe for %s logs: %v", logSource, err)
			select {
			case clientChan <- LogMessage{Message: fmt.Sprintf("[ERROR] Failed to create pipe: %v", err)}:
			default:
			}
			return
		}

		if err := cmd.Start(); err != nil {
			log.Printf("Error starting journalctl for %s logs: %v", logSource, err)
			select {
			case clientChan <- LogMessage{Message: fmt.Sprintf("[ERROR] Failed to start journalctl: %v", err)}:
			default:
			}
			return
		}

		go func() {
			<-ctx.Done()
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		}()

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			jsonLine := scanner.Text()
			var logMsg LogMessage
			if msg, prio, ts, ok := parseJournalJSON(jsonLine); ok {
				logMsg = LogMessage{Message: msg, Priority: prio, Time: ts}
			} else {
				logMsg = LogMessage{Message: jsonLine, Priority: 6}
			}
			select {
			case <-ctx.Done():
				return
			case clientChan <- logMsg:
			default:
				// Channel full, skip message to prevent blocking
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("Scanner error for %s logs: %v", logSource, err)
		}

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

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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

// configEditingBlocked guards config-editing endpoints when the service runs
// in managed mode: AIS-catcher owns its configuration there, so edits to
// config.json/config.cmd would silently have no effect. GETs are sent to the
// system page (where the mode is explained), writes are refused.
func configEditingBlocked(w http.ResponseWriter, r *http.Request) bool {
	managed, _ := getManagedMode()
	if !managed {
		return false
	}
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/control", http.StatusSeeOther)
	} else {
		http.Error(w, "Configuration is managed by AIS-catcher itself (managed mode)", http.StatusConflict)
	}
	return true
}

func makeConfigHandler(title, contentTemplate string) http.HandlerFunc {
	return configPageHandler(title, contentTemplate, true)
}

func makeReadOnlyConfigHandler(title, contentTemplate string) http.HandlerFunc {
	return configPageHandler(title, contentTemplate, false)
}

func configPageHandler(title, contentTemplate string, writable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if configEditingBlocked(w, r) {
			return
		}
		switch {
		case r.Method == http.MethodGet:
			renderTemplateWithConfig(w, title, contentTemplate)
		case r.Method == http.MethodPost && writable:
			if err := saveConfigJSON(w, r); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Configuration saved successfully."))
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

func renderTemplateWithConfig(w http.ResponseWriter, title string, contentTemplate string) {
	if getIntegrityError() {
		renderTemplate(w, "layout.html", map[string]interface{}{
			"Title":           "Configuration Integrity Error",
			"ContentTemplate": "integrity-error",
		})
		return
	}
	renderTemplate(w, "layout.html", map[string]interface{}{
		"CssVersion":      cssVersion,
		"JsVersion":       jsVersion,
		"Title":           title,
		"ContentTemplate": contentTemplate,
	})
}

// jsonPort renders a config "port" value (number or string) as a string.
func jsonPort(v interface{}) string {
	switch p := v.(type) {
	case float64:
		return fmt.Sprintf("%.0f", p)
	case string:
		return p
	}
	return ""
}

type webviewerServer struct {
	Port   string `json:"port"`
	Active bool   `json:"active"`
}

func webviewerHandler(w http.ResponseWriter, r *http.Request) {
	isLoggedIn := isAuthenticated(r)

	hasServer := false
	port := ""
	webviewerActive := false
	serversJSON := template.JS("[]")
	requestedPort := ""

	// In managed mode the embedded viewer page is not used; send the browser
	// to AIS-catcher's own dashboard on the -E port, at the same host the
	// panel is being reached on.
	if managed, _ := getManagedMode(); managed {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		http.Redirect(w, r, "http://"+net.JoinHostPort(host, managedPort()), http.StatusTemporaryRedirect)
		return
	}

	jsonContent, err := readConfigJSON()
	if err == nil && len(jsonContent) > 0 {
		var cfg map[string]interface{}
		if err := json.Unmarshal(jsonContent, &cfg); err == nil {
			if servers, ok := cfg["server"].([]interface{}); ok {
				var entries []webviewerServer
				for _, s := range servers {
					sv, ok := s.(map[string]interface{})
					if !ok {
						continue
					}
					entry := webviewerServer{Active: true, Port: jsonPort(sv["port"])}
					portNum, err := strconv.Atoi(entry.Port)
					if err != nil || portNum < 1 || portNum > 65535 {
						continue
					}
					if active, ok := sv["active"].(bool); ok {
						entry.Active = active
					}
					entries = append(entries, entry)
				}
				if len(entries) > 0 {
					hasServer = true
					port = entries[0].Port
					webviewerActive = entries[0].Active

					// Use port from URL path if provided: /webviewer/{port}
					if suffix := strings.TrimPrefix(r.URL.Path, "/webviewer/"); suffix != "" {
						for _, e := range entries {
							if e.Port == suffix {
								port = e.Port
								webviewerActive = e.Active
								requestedPort = port
								break
							}
						}
					}

					if b, err := json.Marshal(entries); err == nil {
						serversJSON = template.JS(b)
					}
				}
			}
		}
	}

	data := map[string]interface{}{
		"CssVersion":      cssVersion,
		"HasServer":       hasServer,
		"port":            port,
		"WebviewerActive": webviewerActive,
		"ServersJSON":     serversJSON,
		"IsLoggedIn":      isLoggedIn,
		"RequestedPort":   requestedPort,
	}

	renderTemplate(w, "webviewer.html", data)
}

func webviewerToggleHandler(w http.ResponseWriter, r *http.Request) {
	if managed, _ := getManagedMode(); managed {
		sendJSONResponse(w, false, "Configuration is managed by AIS-catcher itself (managed mode)", http.StatusConflict)
		return
	}
	if r.Method != http.MethodPost {
		sendJSONResponse(w, false, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Port   string `json:"port"`
		Active bool   `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, false, "Invalid request body", http.StatusBadRequest)
		return
	}

	portNum, err := strconv.Atoi(req.Port)
	if err != nil || portNum < 1 || portNum > 65535 {
		sendJSONResponse(w, false, "Invalid port", http.StatusBadRequest)
		return
	}

	configFileMu.Lock()
	defer configFileMu.Unlock()

	jsonContent, err := readConfigJSON()
	if err != nil {
		sendJSONResponse(w, false, "Failed to read config", http.StatusInternalServerError)
		return
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(jsonContent, &cfg); err != nil {
		sendJSONResponse(w, false, "Invalid config JSON", http.StatusInternalServerError)
		return
	}

	if configValue, _ := cfg["config"].(string); configValue != "aiscatcher" {
		sendJSONResponse(w, false, "Invalid config", http.StatusBadRequest)
		return
	}

	servers, _ := cfg["server"].([]interface{})
	found := false
	for _, s := range servers {
		sv, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		if jsonPort(sv["port"]) == req.Port {
			sv["active"] = req.Active
			found = true
			break
		}
	}
	if !found {
		servers = append(servers, map[string]interface{}{
			"port":   portNum,
			"active": req.Active,
		})
		cfg["server"] = servers
	}

	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		sendJSONResponse(w, false, "Failed to marshal config", http.StatusInternalServerError)
		return
	}

	if err := writeConfigWithHash(configJSONFilePath, body, setJSONHash); err != nil {
		sendJSONResponse(w, false, "Failed to save config", http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, true, "", http.StatusOK)
}

// renderTemplate executes a named template into a buffer first. If rendering
// succeeds the buffer is written to w; if it fails a clean 500 is returned
// without sending partial HTML.
func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("Template execution error (%s): %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	buf.WriteTo(w)
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

	renderTemplate(w, "layout.html", data)
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

func getFileVersion(staticFSys fs.FS, paths ...string) string {
	h := sha256.New()
	for _, p := range paths {
		f, err := staticFSys.Open(p)
		if err != nil {
			log.Printf("Error opening %s for versioning: %v", p, err)
			return ""
		}
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			log.Printf("Error reading %s for versioning: %v", p, err)
			return ""
		}
		f.Close()
	}
	return hex.EncodeToString(h.Sum(nil))[:8]
}

func apiConfigHandler(w http.ResponseWriter, r *http.Request) {
	if managed, _ := getManagedMode(); managed && r.Method == http.MethodPost {
		http.Error(w, "Configuration is managed by AIS-catcher itself (managed mode)", http.StatusConflict)
		return
	}
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

// statusHandler reports service, uptime and watchdog state for the daemon
// card, served entirely from the cached systemctl show values so any number
// of clients cost one exec per cache refresh.
func statusHandler(w http.ResponseWriter, r *http.Request) {
	sysInfo := getCachedSystemInfo()
	values := sysInfo.UnitProps
	if len(values) == 0 {
		http.Error(w, "failed to query systemctl", http.StatusInternalServerError)
		return
	}

	status := serviceStatusFromProps(values)

	uptime, uptimeSince := "", ""
	if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", values["ActiveEnterTimestamp"]); err == nil {
		uptime = formatDuration(time.Since(t))
		uptimeSince = t.Format("Jan 2, 2006 15:04:05")
	}

	nRestarts, _ := strconv.Atoi(values["NRestarts"])
	burst, _ := strconv.Atoi(values["StartLimitBurst"])
	interval := values["StartLimitIntervalUSec"]
	if interval == "infinity" {
		interval = ""
	}
	exitCode, _ := strconv.Atoi(values["ExecMainStatus"])
	restart := values["Restart"]
	restartDelay := ""
	if restart != "" && restart != "no" {
		restartDelay = values["RestartUSec"]
		if restartDelay == "infinity" {
			restartDelay = ""
		}
	}
	result := values["Result"]
	if result == "success" {
		result = ""
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":               status,
		"running":              values["ActiveState"] == "active",
		"enabled":              values["UnitFileState"] == "enabled",
		"uptime":               uptime,
		"uptime_since":         uptimeSince,
		"pid":                  sysInfo.ProcessID,
		"cpu":                  sysInfo.ProcessCPUUsage,
		"memory":               sysInfo.ProcessMemoryUsage,
		"n_restarts":           nRestarts,
		"watchdog_armed":       strings.Contains(values["OnFailure"], "reboot"),
		"start_limit_hit":      values["SubState"] == "start-limit-hit",
		"start_limit_burst":    burst,
		"start_limit_interval": interval,
		"sub_state":            values["SubState"],
		"result":               result,
		"exit_code":            exitCode,
		"restart":              restart,
		"restart_delay":        restartDelay,
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

const (
	serviceUnitFilePath   = "/etc/systemd/system/ais-catcher.service"
	rebootServiceUnitName = "ais-catcher-reboot.service"
	// Watchdog defaults, matching the install script's --set-reboot-on-failure
	watchdogBurst    = "3"
	watchdogInterval = "1800"
)

// unitSetKey replaces an existing "key=" line in unit-file lines or inserts
// it right after the given section header — the Go equivalent of the install
// script's sed_replace_or_insert.
func unitSetKey(lines []string, key, val, section string) []string {
	prefix := key + "="
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			lines[i] = key + "=" + val
			return lines
		}
	}
	header := "[" + section + "]"
	for i, l := range lines {
		if strings.TrimSpace(l) == header {
			out := append([]string{}, lines[:i+1]...)
			out = append(out, key+"="+val)
			return append(out, lines[i+1:]...)
		}
	}
	return lines
}

func unitRemoveKey(lines []string, key string) []string {
	prefix := key + "="
	out := lines[:0]
	for _, l := range lines {
		if !strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

func unitHasKey(lines []string, key string) bool {
	prefix := key + "="
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

// applyServicePolicy edits the systemd unit for the watchdog / auto-restart
// toggles — the same keys the install script's --set-reboot-on-failure and
// --set-auto-restart set, applied natively so no script download is needed.
func applyServicePolicy(action string, lines []string) []string {
	switch action {
	case "watchdog-on":
		lines = unitSetKey(lines, "StartLimitBurst", watchdogBurst, "Unit")
		lines = unitSetKey(lines, "StartLimitIntervalSec", watchdogInterval, "Unit")
		if !unitHasKey(lines, "OnFailure") {
			lines = unitSetKey(lines, "OnFailure", rebootServiceUnitName, "Unit")
		}
	case "watchdog-off":
		lines = unitSetKey(lines, "StartLimitBurst", "0", "Unit")
		lines = unitSetKey(lines, "StartLimitIntervalSec", "0", "Unit")
		// With burst=0 OnFailure would fire on every crash, not just limit-hit
		lines = unitRemoveKey(lines, "OnFailure")
	case "auto-restart-on":
		lines = unitSetKey(lines, "Restart", "always", "Service")
	case "auto-restart-off":
		lines = unitSetKey(lines, "Restart", "no", "Service")
	}
	return lines
}

// servicePolicyHandler toggles the reboot watchdog / auto-restart policy by
// editing the service unit and reloading systemd. Policy directives take
// effect on the next crash/start, so the service is not restarted.
func servicePolicyHandler(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendJSONResponse(w, false, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		data, err := os.ReadFile(serviceUnitFilePath)
		if err != nil {
			sendJSONResponse(w, false, "ais-catcher.service not found — is AIS-catcher installed?", http.StatusConflict)
			return
		}
		if action == "watchdog-on" {
			if _, err := os.Stat("/etc/systemd/system/" + rebootServiceUnitName); err != nil {
				sendJSONResponse(w, false, rebootServiceUnitName+" not found — update AIS-catcher first", http.StatusConflict)
				return
			}
		}

		lines := applyServicePolicy(action, strings.Split(string(data), "\n"))
		if err := writeFileAtomic(serviceUnitFilePath, []byte(strings.Join(lines, "\n")), 0644); err != nil {
			log.Printf("Service policy write error (%s): %v", action, err)
			sendJSONResponse(w, false, "failed to write service file", http.StatusInternalServerError)
			return
		}

		if _, err := runCmd(10*time.Second, "systemctl", "daemon-reload"); err != nil {
			log.Printf("daemon-reload failed after %s: %v", action, err)
			sendJSONResponse(w, false, "systemd reload failed", http.StatusInternalServerError)
			return
		}
		runCmd(10*time.Second, "systemctl", "reset-failed", "ais-catcher.service")

		sendJSONResponse(w, true, "", http.StatusOK)
	}
}

// makeEditorHandler serves the raw text editor for a panel-owned config file.
// validate may be nil; it rejects content before anything is written.
func makeEditorHandler(title, tmpl, path string, set func(*Config, uint32), validate func(string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if configEditingBlocked(w, r) {
			return
		}
		switch r.Method {
		case http.MethodGet:
			content, err := os.ReadFile(path)
			if err != nil {
				log.Printf("Error reading %s: %v", path, err)
				content = []byte("")
			}
			renderEditorTemplate(w, title, tmpl, string(content), "", "")
		case http.MethodPost:
			newContent := r.FormValue("file_content")
			if validate != nil {
				if err := validate(newContent); err != nil {
					renderEditorTemplate(w, title, tmpl, newContent, err.Error(), "")
					return
				}
			}
			configFileMu.Lock()
			defer configFileMu.Unlock()
			if err := writeConfigWithHash(path, []byte(newContent), set); err != nil {
				renderEditorTemplate(w, title, tmpl, newContent, err.Error(), "")
				return
			}
			renderEditorTemplate(w, title, tmpl, newContent, "", "Configuration saved successfully.")
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

func validateJSONText(content string) error {
	var jsonMap map[string]interface{}
	if err := json.Unmarshal([]byte(content), &jsonMap); err != nil {
		return fmt.Errorf("Invalid JSON: %v", err)
	}
	return nil
}

// systemRedirectHandler preserves old /system links (bookmarks, update-card
// deep links with ?action=...) now that the page is merged into /control.
func systemRedirectHandler(w http.ResponseWriter, r *http.Request) {
	target := "/control"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// systemStatusAPIHandler provides real-time system status as JSON
func systemStatusAPIHandler(w http.ResponseWriter, r *http.Request) {
	sysInfo := getCachedSystemInfo()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sysInfo)
}

// watchdogStatusHandler returns the reboot-on-failure watchdog status for ais-catcher.service

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

	cachedSysInfo.info = collectSystemInfo(cachedSysInfo.info)
	cachedSysInfo.lastFetch = time.Now()

	err = loadControlSettings()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	staticFSys, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal("Failed to create sub filesystem:", err)
	}

	cssVersion = getFileVersion(staticFSys, "css/tailwind.css")
	jsVersion = getFileVersion(staticFSys, "js/config-manager.js", "js/schema.js")

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
	http.HandleFunc("/api/reset-failed", authMiddleware(serviceActionHandler("reset-failed")))
	http.HandleFunc("/api/watchdog-on", authMiddleware(servicePolicyHandler("watchdog-on")))
	http.HandleFunc("/api/watchdog-off", authMiddleware(servicePolicyHandler("watchdog-off")))
	http.HandleFunc("/api/auto-restart-on", authMiddleware(servicePolicyHandler("auto-restart-on")))
	http.HandleFunc("/api/auto-restart-off", authMiddleware(servicePolicyHandler("auto-restart-off")))
	http.HandleFunc("/api/recent-logs", authMiddleware(recentLogsHandler))
	http.HandleFunc("/logs-stream", authMiddleware(logsStreamHandler))
	http.HandleFunc("/status", authMiddleware(statusHandler))
	http.HandleFunc("/device", authMiddleware(makeConfigHandler("Device Configuration", "device-setup")))
	http.HandleFunc("/server", authMiddleware(makeConfigHandler("Webviewer Setup", "server-setup")))
	http.HandleFunc("/webviewer", webviewerHandler)
	http.HandleFunc("/webviewer/", webviewerHandler)
	http.HandleFunc("/api/webviewer/toggle", authMiddleware(webviewerToggleHandler))
	http.HandleFunc("/logout", authMiddleware(logoutHandler))
	http.HandleFunc("/device-list", authMiddleware(deviceListHandler))
	http.HandleFunc("/serial-list", authMiddleware(serialListHandler))
	http.HandleFunc("/editjson", authMiddleware(makeEditorHandler("Edit config.json", "edit-config-json", configJSONFilePath, setJSONHash, validateJSONText)))
	http.HandleFunc("/editcmd", authMiddleware(makeEditorHandler("Edit config.cmd", "edit-config-cmd", configCmdFilePath, setCmdHash, nil)))
	http.HandleFunc("/system", authMiddleware(systemRedirectHandler))
	http.HandleFunc("/api/system-action-start", authMiddleware(systemActionStartHandler))
	http.HandleFunc("/system-action-progress", authMiddleware(systemActionProgressHandler))
	http.HandleFunc("/system-action-status", authMiddleware(systemActionStatusHandler))
	http.HandleFunc("/api/system-status", authMiddleware(systemStatusAPIHandler))
	http.HandleFunc("/tcp-servers", authMiddleware(makeConfigHandler("TCP Servers", "tcp-servers")))
	http.HandleFunc("/general", authMiddleware(makeConfigHandler("General Settings", "general-settings")))
	http.HandleFunc("/dataflow", authMiddleware(makeReadOnlyConfigHandler("Data Flow", "zones")))
	http.HandleFunc("/api/reboot-pending", authMiddleware(rebootPendingHandler))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !getConfig().LicenseAccepted {
			http.Redirect(w, r, "/license", http.StatusSeeOther)
			return
		}
		if isAuthenticated(r) {
			http.Redirect(w, r, "/control", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	addr := ":" + getConfig().Port
	log.Printf("Server started at %s\n", addr)
	server := &http.Server{
		Addr: addr,
		// write/idle timeouts stay unset: SSE endpoints hold connections open
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
