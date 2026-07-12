package main

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseExecStartManaged(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		managed bool
		bind    string
	}{
		{
			name:    "managed",
			line:    "ExecStart={ path=/usr/bin/AIS-catcher ; argv[]=/usr/bin/AIS-catcher -E /etc/AIS-catcher/aiscatcher.json 0.0.0.0:8118 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
			managed: true,
			bind:    "0.0.0.0:8118",
		},
		{
			name:    "managed without bind falls back to default",
			line:    "ExecStart={ path=/usr/bin/AIS-catcher ; argv[]=/usr/bin/AIS-catcher -E /etc/AIS-catcher/aiscatcher.json ; ignore_errors=no }",
			managed: true,
			bind:    "0.0.0.0:8118",
		},
		{
			name:    "unmanaged",
			line:    "ExecStart={ path=/usr/bin/AIS-catcher ; argv[]=/usr/bin/AIS-catcher -G system on -o 0 -C /etc/AIS-catcher/config.json @/etc/AIS-catcher/config.cmd ; ignore_errors=no }",
			managed: false,
			bind:    "",
		},
		{
			name:    "no unit",
			line:    "ExecStart=\n",
			managed: false,
			bind:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			managed, bind := parseExecStartManaged(tt.line)
			if managed != tt.managed || bind != tt.bind {
				t.Errorf("parseExecStartManaged() = (%v, %q), want (%v, %q)", managed, bind, tt.managed, tt.bind)
			}
		})
	}
}

// The install script rewrites the systemd unit on every install, so updates
// started from the panel must carry the mode flag or a managed system would
// silently revert to unmanaged.
func TestActionScriptsCarryModeFlag(t *testing.T) {
	managedModeCache.Lock()
	managedModeCache.managed = true
	managedModeCache.bind = "0.0.0.0:8118"
	managedModeCache.checked = time.Now()
	managedModeCache.Unlock()

	for _, action := range []string{"ais-update-prebuilt", "ais-update-source", "update-all", "update-all-reboot"} {
		script, _ := getActionScript(action)
		if script == "" {
			t.Fatalf("no script for action %q", action)
		}
		if !strings.Contains(script, "-M") {
			t.Errorf("action %q does not preserve managed mode: %s", action, script)
		}
	}

	if script, _ := getActionScript("switch-managed"); !strings.Contains(script, "-p -M") {
		t.Errorf("switch-managed should install prebuilt with -M: %s", script)
	}
	if script, _ := getActionScript("switch-unmanaged"); strings.Contains(script, "-M") {
		t.Errorf("switch-unmanaged must not pass -M: %s", script)
	}
}

func TestApplyServicePolicy(t *testing.T) {
	unit := `[Unit]
Description=AIS-catcher
After=network.target

[Service]
ExecStart=/usr/bin/AIS-catcher -E /etc/AIS-catcher/aiscatcher.json 0.0.0.0:8118
Restart=no
RestartSec=10

[Install]
WantedBy=multi-user.target`

	join := func(lines []string) string { return strings.Join(lines, "\n") }
	split := func(s string) []string { return strings.Split(s, "\n") }

	on := join(applyServicePolicy("watchdog-on", split(unit)))
	for _, want := range []string{"StartLimitBurst=3", "StartLimitIntervalSec=1800", "OnFailure=ais-catcher-reboot.service"} {
		if !strings.Contains(on, want) {
			t.Errorf("watchdog-on missing %q:\n%s", want, on)
		}
	}
	// Keys must land in [Unit], i.e. before the [Service] header
	if strings.Index(on, "OnFailure=") > strings.Index(on, "[Service]") {
		t.Error("OnFailure inserted outside the [Unit] section")
	}

	off := join(applyServicePolicy("watchdog-off", split(on)))
	if strings.Contains(off, "OnFailure=") {
		t.Errorf("watchdog-off left OnFailure in place:\n%s", off)
	}
	if !strings.Contains(off, "StartLimitBurst=0") || !strings.Contains(off, "StartLimitIntervalSec=0") {
		t.Errorf("watchdog-off did not zero the start limits:\n%s", off)
	}

	ar := join(applyServicePolicy("auto-restart-on", split(unit)))
	if !strings.Contains(ar, "Restart=always") || strings.Contains(ar, "Restart=no") {
		t.Errorf("auto-restart-on did not replace Restart=no:\n%s", ar)
	}
	arOff := join(applyServicePolicy("auto-restart-off", split(ar)))
	if !strings.Contains(arOff, "Restart=no") {
		t.Errorf("auto-restart-off did not set Restart=no:\n%s", arOff)
	}
	// RestartSec must never be clobbered by the Restart= prefix match
	if !strings.Contains(ar, "RestartSec=10") || !strings.Contains(arOff, "RestartSec=10") {
		t.Error("RestartSec was clobbered by the Restart toggle")
	}
}

func TestWebviewerRedirectsInManagedMode(t *testing.T) {
	managedModeCache.Lock()
	managedModeCache.managed = true
	managedModeCache.bind = "0.0.0.0:8118"
	managedModeCache.checked = time.Now()
	managedModeCache.Unlock()

	req := httptest.NewRequest("GET", "/webviewer", nil)
	req.Host = "192.168.1.10:8110"
	rec := httptest.NewRecorder()
	webviewerHandler(rec, req)

	if rec.Code != 307 {
		t.Fatalf("expected 307 redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "http://192.168.1.10:8118" {
		t.Errorf("expected redirect to AIS-catcher dashboard on -E port, got %q", loc)
	}
}

func TestLayoutRendersInManagedMode(t *testing.T) {
	managedModeCache.Lock()
	managedModeCache.managed = true
	managedModeCache.bind = "0.0.0.0:8118"
	managedModeCache.checked = time.Now()
	managedModeCache.Unlock()

	var buf bytes.Buffer
	data := map[string]interface{}{
		"Title":           "Control Dashboard",
		"ContentTemplate": "control",
		"SystemInfo":      SystemInfo{ManagedMode: true, ManagedPort: "8118", AISCatcherAvailable: true},
		"MemoryGB":        1.0,
	}
	if err := templates.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		t.Fatalf("layout.html failed to render in managed mode: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, "managed-settings-link") {
		t.Error("managed nav link missing")
	}
	if strings.Contains(html, `href="/general"`) {
		t.Error("config-editing nav should be hidden in managed mode")
	}
	if strings.Contains(html, `href="/webviewer"`) {
		t.Error("viewer nav should be hidden in managed mode")
	}
	if !strings.Contains(html, "Open AIS-catcher Control") {
		t.Error("managed banner missing on system page")
	}

	// Unmanaged: config nav present, switch banner shown
	managedModeCache.Lock()
	managedModeCache.managed = false
	managedModeCache.bind = ""
	managedModeCache.checked = time.Now()
	managedModeCache.Unlock()

	buf.Reset()
	data["SystemInfo"] = SystemInfo{AISCatcherAvailable: true}
	if err := templates.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		t.Fatalf("layout.html failed to render in unmanaged mode: %v", err)
	}
	html = buf.String()
	if !strings.Contains(html, `href="/general"`) {
		t.Error("config-editing nav missing in unmanaged mode")
	}
	if !strings.Contains(html, `href="/webviewer"`) {
		t.Error("viewer nav missing in unmanaged mode")
	}
	if !strings.Contains(html, "Switch to Managed Mode") {
		t.Error("switch-to-managed banner missing on system page")
	}
}
