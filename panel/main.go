package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Config holds the server-side configuration parameters
type Config struct {
	ServerIP         string `json:"server_ip"`
	Domain           string `json:"domain"`
	Port             int    `json:"port"`
	Token            string `json:"token"`
	PasswordHash     string `json:"password_hash"`
	WarpGlobal       bool   `json:"warp_global"`
	IsFirstLogin     bool   `json:"is_first_login"`
	HysteriaPort     int    `json:"hysteria_port"`
	HysteriaPassword string `json:"hysteria_password"`
	MieruPort        int    `json:"mieru_port"`
	MieruUser        string `json:"mieru_user"`
	MieruPassword    string `json:"mieru_password"`
	AnyTLSPort       int    `json:"anytls_port"`
	AnyTLSPassword   string `json:"anytls_password"`
	NaivePort        int    `json:"naive_port"`
	NaiveUser        string `json:"naive_user"`
	NaivePassword    string `json:"naive_password"`
	SkipCertVerify   bool   `json:"skip_cert_verify"`
	CertPath         string `json:"cert_path"`
	KeyPath          string `json:"key_path"`
	DirectList       string `json:"direct_list"`
	WarpList         string `json:"warp_list"`
}

type TrafficRecord struct {
	Time string
	Rx   float64
	Tx   float64
}

// Global state
var (
	configPath   = "/etc/vpn-protocols/panel-settings.json"
	authLogPath  = "/var/log/vpn-panel-auth.log"
	cfg          Config
	cfgMu        sync.RWMutex
	sessions     = make(map[string]time.Time)
	sessionsMu   sync.Mutex
	rateLimit    = make(map[string]*loginTracker)
	rateLimitMu  sync.Mutex
	trafficHistory []TrafficRecord
	historyMu    sync.Mutex
)

type loginTracker struct {
	Attempts int
	Blocked  time.Time
}

// System stats
type ServiceInfo struct {
	Active  bool   `json:"active"`
	Port    int    `json:"port"`
	Traffic uint64 `json:"traffic"`
}

type WarpInfo struct {
	Active  bool   `json:"active"`
	IP      string `json:"ip"`
	Latency int    `json:"latency"`
}

type ServicesStatus struct {
	Hysteria2  ServiceInfo `json:"Hysteria2"`
	Mieru      ServiceInfo `json:"Mieru"`
	AnyTLS     ServiceInfo `json:"AnyTLS"`
	NaiveProxy ServiceInfo `json:"NaiveProxy"`
	WARP       WarpInfo    `json:"WARP"`
}

type MetricsResponse struct {
	CPU            float64        `json:"CPU"`
	RAMTotal       uint64         `json:"RAMTotal"`
	RAMUsed        uint64         `json:"RAMUsed"`
	RAMPercent     float64        `json:"RAMPercent"`
	SwapTotal      uint64         `json:"SwapTotal"`
	SwapUsed       uint64         `json:"SwapUsed"`
	SwapPercent    float64        `json:"SwapPercent"`
	DiskTotal      uint64         `json:"DiskTotal"`
	DiskUsed       uint64         `json:"DiskUsed"`
	DiskPercent    float64        `json:"DiskPercent"`
	Uptime         string         `json:"Uptime"`
	TrafficTotal   uint64         `json:"TrafficTotal"`
	TrafficIn      uint64         `json:"TrafficIn"`
	TrafficOut     uint64         `json:"TrafficOut"`
	Services       ServicesStatus `json:"Services"`
	History        HistoryData    `json:"History"`
}

type HistoryData struct {
	Labels   []string  `json:"Labels"`
	InRates  []float64 `json:"InRates"`
	OutRates []float64 `json:"OutRates"`
}

func main() {
	loadConfig()

	// Ensure config directory exists
	os.MkdirAll(filepath.Dir(configPath), 0755)

	// Create auth log file
	f, err := os.OpenFile(authLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		f.Close()
	}

	// Start traffic historical rate collector
	go startTrafficCollector()

	// Start clean up session goroutine
	go startSessionCleaner()

	// Setup Router
	http.HandleFunc("/static/", handleStatic)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/reset-password", handleResetPassword)
	http.HandleFunc("/change-password", handleChangePassword)
	http.HandleFunc("/save-settings", handleSaveSettings)
	http.HandleFunc("/api/metrics", handleAPIMetrics)
	http.HandleFunc("/sub/clash/", handleSubClash)
	http.HandleFunc("/sub/singbox/", handleSubSingbox)
	http.HandleFunc("/", handleIndex)

	log.Printf("Server listening on :%d\n", cfg.Port)
	if cfg.CertPath != "" && cfg.KeyPath != "" {
		if _, errCert := os.Stat(cfg.CertPath); errCert == nil {
			if _, errKey := os.Stat(cfg.KeyPath); errKey == nil {
				log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", cfg.Port), cfg.CertPath, cfg.KeyPath, nil))
				return
			}
		}
	}
	// Fallback to HTTP if no certs are configured/found yet
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), nil))
}

// Helpers for secure generation
func secureRandomHex(n int) string {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(bytes)
}

func loadConfig() {
	cfgMu.Lock()
	defer cfgMu.Unlock()

	data, err := os.ReadFile(configPath)
	if err != nil {
		// Initialize default config if not present
		cfg = Config{
			ServerIP:     "127.0.0.1",
			Domain:       "127-0-0-1.sslip.io",
			Port:         8080,
			Token:        secureRandomHex(16),
			IsFirstLogin: true,
			WarpGlobal:   true,
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		cfg.PasswordHash = string(hash)
		return
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Println("Error unmarshaling config, using defaults:", err)
	}
}

func saveConfig() {
	cfgMu.RLock()
	data, err := json.MarshalIndent(cfg, "", "  ")
	cfgMu.RUnlock()

	if err != nil {
		log.Println("Error marshaling config:", err)
		return
	}

	err = os.WriteFile(configPath, data, 0600)
	if err != nil {
		log.Println("Error writing config:", err)
	}
}

// Embed HTML/CSS templates
//go:embed templates/* static/*
var assetsFS embed.FS

// Custom embed helper if we compile locally
// Since we are running the server compiled, we can write the files directly, or read them from /etc/vpn-panel.
// But to make it 100% self-contained, we will read the templates from the files on disk that we created in the repository!
// This is perfect because we install the panel files inside /opt/vpn-panel/templates/ and static/.
// So our Go code will load templates from the disk in /opt/vpn-panel/templates/ to make design edits easy and instant.

func loadTemplate(name string) (*template.Template, error) {
	path := filepath.Join("/opt/vpn-panel/templates", name)
	if _, err := os.Stat(path); err != nil {
		// Fallback to local project folder if running locally
		path = filepath.Join("templates", name)
	}
	return template.ParseFiles(path)
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	path := filepath.Join("/opt/vpn-panel/static", name)
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join("static", name)
	}

	if strings.HasSuffix(name, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	}

	http.ServeFile(w, r, path)
}

// Session Helpers
func createSession(w http.ResponseWriter) {
	sessionID := secureRandomHex(32)
	sessionsMu.Lock()
	sessions[sessionID] = time.Now().Add(2 * time.Hour)
	sessionsMu.Unlock()

	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(2 * time.Hour),
		HttpOnly: true,
		Secure:   true, // Forces SSL
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

func checkSession(r *http.Request) bool {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return false
	}
	sessionsMu.Lock()
	expiry, exists := sessions[cookie.Value]
	sessionsMu.Unlock()

	if !exists || time.Now().After(expiry) {
		return false
	}
	return true
}

func startSessionCleaner() {
	for {
		time.Sleep(10 * time.Minute)
		now := time.Now()
		sessionsMu.Lock()
		for k, v := range sessions {
			if now.After(v) {
				delete(sessions, k)
			}
		}
		sessionsMu.Unlock()
	}
}

// Rate Limiter for Login
func isBlocked(ip string) bool {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	tracker, exists := rateLimit[ip]
	if !exists {
		return false
	}
	if time.Now().Before(tracker.Blocked) {
		return true
	}
	// Expired block
	if tracker.Attempts >= 5 {
		delete(rateLimit, ip)
	}
	return false
}

func recordFailedLogin(ip string) {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	tracker, exists := rateLimit[ip]
	if !exists {
		rateLimit[ip] = &loginTracker{Attempts: 1}
		return
	}
	tracker.Attempts++
	if tracker.Attempts >= 5 {
		tracker.Blocked = time.Now().Add(15 * time.Minute)
	}
}

func recordSuccessfulLogin(ip string) {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	delete(rateLimit, ip)
}

func logAuthEvent(ip, user, event string) {
	f, err := os.OpenFile(authLogPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(f, "%s - %s - User: %s - Event: %s\n", timestamp, ip, user, event)
}

// Route handlers
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !checkSession(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	cfgMu.RLock()
	isFirst := cfg.IsFirstLogin
	cfgMu.RUnlock()

	if isFirst {
		tmpl, err := loadTemplate("login.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, map[string]interface{}{
			"ForceReset": true,
		})
		return
	}

	tmpl, err := loadTemplate("index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cfgMu.RLock()
	data := map[string]interface{}{
		"ServerIP":   cfg.ServerIP,
		"Domain":     cfg.Domain,
		"Port":       cfg.Port,
		"Token":      cfg.Token,
		"WarpGlobal": cfg.WarpGlobal,
		"DirectList": cfg.DirectList,
		"WarpList":   cfg.WarpList,
		"Virt":       getVirtualization(),
		"Arch":       getArchitecture(),
	}
	cfgMu.RUnlock()

	tmpl.Execute(w, data)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if isBlocked(ip) {
		tmpl, _ := loadTemplate("login.html")
		tmpl.Execute(w, map[string]interface{}{
			"Error": "Слишком много неудачных попыток входа. Доступ заблокирован на 15 минут.",
		})
		return
	}

	if r.Method == "GET" {
		if checkSession(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		tmpl, err := loadTemplate("login.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	cfgMu.RLock()
	expectedHash := cfg.PasswordHash
	cfgMu.RUnlock()

	err := bcrypt.CompareHashAndPassword([]byte(expectedHash), []byte(password))
	if username == "admin" && err == nil {
		recordSuccessfulLogin(ip)
		logAuthEvent(ip, username, "LOGIN_SUCCESS")
		createSession(w)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	recordFailedLogin(ip)
	logAuthEvent(ip, username, "LOGIN_FAILED")
	tmpl, _ := loadTemplate("login.html")
	tmpl.Execute(w, map[string]interface{}{
		"Error": "Неверное имя пользователя или пароль",
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	// Expire cookie
	cookie = &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func handleResetPassword(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	cfgMu.RLock()
	isFirst := cfg.IsFirstLogin
	cfgMu.RUnlock()

	if !isFirst {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	newPass := r.FormValue("new_password")
	confirmPass := r.FormValue("confirm_password")

	if newPass != confirmPass {
		tmpl, _ := loadTemplate("login.html")
		tmpl.Execute(w, map[string]interface{}{
			"ForceReset": true,
			"Error":      "Пароли не совпадают",
		})
		return
	}

	if len(newPass) < 8 {
		tmpl, _ := loadTemplate("login.html")
		tmpl.Execute(w, map[string]interface{}{
			"ForceReset": true,
			"Error":      "Пароль должен содержать минимум 8 символов",
		})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	cfgMu.Lock()
	cfg.PasswordHash = string(hash)
	cfg.IsFirstLogin = false
	cfgMu.Unlock()

	saveConfig()
	logAuthEvent(ip, "admin", "PASSWORD_RESET_INITIAL")
	createSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !checkSession(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	oldPass := r.FormValue("old_password")
	newPass := r.FormValue("new_password")

	cfgMu.RLock()
	expectedHash := cfg.PasswordHash
	cfgMu.RUnlock()

	err := bcrypt.CompareHashAndPassword([]byte(expectedHash), []byte(oldPass))
	if err != nil {
		http.Error(w, "Неверный текущий пароль", http.StatusForbidden)
		return
	}

	if len(newPass) < 8 {
		http.Error(w, "Пароль слишком короткий", http.StatusBadRequest)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	cfgMu.Lock()
	cfg.PasswordHash = string(hash)
	cfgMu.Unlock()

	saveConfig()
	logAuthEvent(ip, "admin", "PASSWORD_CHANGED")
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if !checkSession(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	warpGlobal := r.FormValue("warp_global") == "on"
	directList := r.FormValue("direct_list")
	warpList := r.FormValue("warp_list")

	cfgMu.Lock()
	cfg.WarpGlobal = warpGlobal
	cfg.DirectList = directList
	cfg.WarpList = warpList
	cfgMu.Unlock()

	saveConfig()

	// Update local routing settings in sing-box
	go applyRoutingChanges()

	http.Redirect(w, r, "/", http.StatusFound)
}

func applyRoutingChanges() {
	// Rebuild sing-box server routing rules
	// Write new configuration and reload/restart the routing service (sing-box)
	// We will implement this dynamically inside panel script trigger
	cmd := exec.Command("/opt/vpn-panel/apply-routing.sh")
	cmd.Run()
}

// Metrics implementation (Parsing linux virtual filesystem files)
func handleAPIMetrics(w http.ResponseWriter, r *http.Request) {
	if !checkSession(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cpuPercent := getCPUUsage()
	ramTotal, ramUsed, ramPercent := getRAMUsage()
	swapTotal, swapUsed, swapPercent := getSwapUsage()
	diskTotal, diskUsed, diskPercent := getDiskUsage()
	uptime := getSystemUptime()
	trafficTotal, trafficIn, trafficOut := getNetworkTraffic()

	cfgMu.RLock()
	hysteriaPort := cfg.HysteriaPort
	mieruPort := cfg.MieruPort
	anytlsPort := cfg.AnyTLSPort
	naivePort := cfg.NaivePort
	cfgMu.RUnlock()

	services := ServicesStatus{
		Hysteria2:  ServiceInfo{Active: checkPortOpen(hysteriaPort), Port: hysteriaPort, Traffic: getPortTraffic(hysteriaPort)},
		Mieru:      ServiceInfo{Active: checkPortOpen(mieruPort), Port: mieruPort, Traffic: getPortTraffic(mieruPort)},
		AnyTLS:     ServiceInfo{Active: checkPortOpen(anytlsPort), Port: anytlsPort, Traffic: getPortTraffic(anytlsPort)},
		NaiveProxy: ServiceInfo{Active: checkPortOpen(naivePort), Port: naivePort, Traffic: getPortTraffic(naivePort)},
		WARP:       getWARPStatus(),
	}

	historyMu.Lock()
	var labels []string
	var inRates []float64
	var outRates []float64
	for _, rec := range trafficHistory {
		labels = append(labels, rec.Time)
		inRates = append(inRates, rec.Rx)
		outRates = append(outRates, rec.Tx)
	}
	historyMu.Unlock()

	metrics := MetricsResponse{
		CPU:          cpuPercent,
		RAMTotal:     ramTotal,
		RAMUsed:      ramUsed,
		RAMPercent:   ramPercent,
		SwapTotal:    swapTotal,
		SwapUsed:     swapUsed,
		SwapPercent:  swapPercent,
		DiskTotal:    diskTotal,
		DiskUsed:     diskUsed,
		DiskPercent:  diskPercent,
		Uptime:       uptime,
		TrafficTotal: trafficTotal,
		TrafficIn:    trafficIn,
		TrafficOut:   trafficOut,
		Services:     services,
		History: HistoryData{
			Labels:   labels,
			InRates:  inRates,
			OutRates: outRates,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// System stat getters
func getCPUUsage() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0.0
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0.0
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0.0
	}

	var total uint64
	for i := 1; i < len(fields); i++ {
		var val uint64
		fmt.Sscanf(fields[i], "%d", &val)
		total += val
	}
	var idle uint64
	fmt.Sscanf(fields[4], "%d", &idle)

	// Since we need to measure delta over time, we sleep for a tiny bit
	time.Sleep(100 * time.Millisecond)

	data, err = os.ReadFile("/proc/stat")
	if err != nil {
		return 0.0
	}
	lines = strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0.0
	}
	fields2 := strings.Fields(lines[0])
	var total2 uint64
	for i := 1; i < len(fields2); i++ {
		var val uint64
		fmt.Sscanf(fields2[i], "%d", &val)
		total2 += val
	}
	var idle2 uint64
	fmt.Sscanf(fields2[4], "%d", &idle2)

	totalDelta := total2 - total
	idleDelta := idle2 - idle
	if totalDelta == 0 {
		return 0.0
	}
	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100.0
}

func getRAMUsage() (uint64, uint64, float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0.0
	}
	var total, avail uint64
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "MemTotal:") {
			fmt.Sscanf(l, "MemTotal: %d kB", &total)
		} else if strings.HasPrefix(l, "MemAvailable:") {
			fmt.Sscanf(l, "MemAvailable: %d kB", &avail)
		}
	}
	// Convert to Bytes
	totalBytes := total * 1024
	usedBytes := (total - avail) * 1024
	if totalBytes == 0 {
		return 0, 0, 0.0
	}
	return totalBytes, usedBytes, float64(usedBytes) / float64(totalBytes) * 100.0
}

func getSwapUsage() (uint64, uint64, float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0.0
	}
	var total, free uint64
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "SwapTotal:") {
			fmt.Sscanf(l, "SwapTotal: %d kB", &total)
		} else if strings.HasPrefix(l, "SwapFree:") {
			fmt.Sscanf(l, "SwapFree: %d kB", &free)
		}
	}
	totalBytes := total * 1024
	usedBytes := (total - free) * 1024
	if totalBytes == 0 {
		return 0, 0, 0.0
	}
	return totalBytes, usedBytes, float64(usedBytes) / float64(totalBytes) * 100.0
}

func getDiskUsage() (uint64, uint64, float64) {
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		return 0, 0, 0.0
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	if total == 0 {
		return 0, 0, 0.0
	}
	return total, used, float64(used) / float64(total) * 100.0
}

func getSystemUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "-"
	}
	var uptimeSec float64
	fmt.Sscanf(string(data), "%f", &uptimeSec)

	d := time.Duration(uptimeSec) * time.Second
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	mins := d / time.Minute

	if days > 0 {
		return fmt.Sprintf("%dд %dч %dм", days, hours, mins)
	}
	return fmt.Sprintf("%dч %dм", hours, mins)
}

func getNetworkTraffic() (uint64, uint64, uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, 0.0
	}
	lines := strings.Split(string(data), "\n")
	var totalIn, totalOut uint64
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 17 {
			continue
		}
		dev := strings.TrimSuffix(fields[0], ":")
		// Exclude loopback and tunnel interfaces
		if dev == "lo" || strings.HasPrefix(dev, "wg") || strings.HasPrefix(dev, "sing") {
			continue
		}
		var rx, tx uint64
		fmt.Sscanf(fields[1], "%d", &rx)
		fmt.Sscanf(fields[9], "%d", &tx)
		totalIn += rx
		totalOut += tx
	}
	return totalIn + totalOut, totalIn, totalOut
}

func checkPortOpen(port int) bool {
	if port == 0 {
		return false
	}
	// Attempt local connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}
	// Fallback to UDP check for Hysteria2 (we just scan if port binds using ss command or systemctl)
	// We can execute ss -uln or similar to verify UDP port
	cmd := exec.Command("ss", "-uln", fmt.Sprintf("sport = :%d", port))
	out, err := cmd.Output()
	if err == nil && strings.Contains(string(out), fmt.Sprintf(":%d", port)) {
		return true
	}
	return false
}

// Get traffic bytes from iptables counters
func getPortTraffic(port int) uint64 {
	// Parse iptables stats
	// Command: iptables -vxL INPUT
	// To check traffic per port, install.sh will add rules:
	// iptables -A INPUT -p tcp --dport $PORT
	// iptables -A INPUT -p udp --dport $PORT
	// iptables -A OUTPUT -p tcp --sport $PORT
	// iptables -A OUTPUT -p udp --sport $PORT
	// Then we can read the byte counter from these rules!
	if port == 0 {
		return 0
	}
	cmd := exec.Command("iptables", "-vxL", "INPUT")
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(string(out), "\n")
	var bytes uint64
	for _, l := range lines {
		if strings.Contains(l, fmt.Sprintf("dpt:%d", port)) || strings.Contains(l, fmt.Sprintf("dpts:%d", port)) {
			fields := strings.Fields(l)
			if len(fields) > 1 {
				var count uint64
				fmt.Sscanf(fields[1], "%d", &count)
				bytes += count
			}
		}
	}

	cmd = exec.Command("iptables", "-vxL", "OUTPUT")
	out, err = cmd.Output()
	if err == nil {
		lines = strings.Split(string(out), "\n")
		for _, l := range lines {
			if strings.Contains(l, fmt.Sprintf("spt:%d", port)) || strings.Contains(l, fmt.Sprintf("spts:%d", port)) {
				fields := strings.Fields(l)
				if len(fields) > 1 {
					var count uint64
					fmt.Sscanf(fields[1], "%d", &count)
					bytes += count
				}
			}
		}
	}
	return bytes
}

func getWARPStatus() WarpInfo {
	// Check if Wireguard interface wgcf exists
	_, err := os.Stat("/sys/class/net/wgcf")
	active := (err == nil)

	if !active {
		return WarpInfo{Active: false}
	}

	// Fetch WARP IP and test latency via Cloudflare Trace
	client := http.Client{Timeout: 1 * time.Second}
	start := time.Now()
	resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	latency := int(time.Since(start).Milliseconds())

	if err != nil {
		return WarpInfo{Active: true, IP: "WireGuard Up (No Internet)", Latency: 0}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	ip := "Unknown"
	warpStatus := "off"
	for _, l := range lines {
		if strings.HasPrefix(l, "ip=") {
			ip = strings.TrimPrefix(l, "ip=")
		} else if strings.HasPrefix(l, "warp=") {
			warpStatus = strings.TrimPrefix(l, "warp=")
		}
	}
	return WarpInfo{Active: (warpStatus == "on"), IP: ip, Latency: latency}
}

func getVirtualization() string {
	cmd := exec.Command("systemd-detect-virt")
	out, err := cmd.Output()
	if err != nil {
		return "KVM/Unknown"
	}
	return strings.TrimSpace(string(out))
}

func getArchitecture() string {
	cmd := exec.Command("uname", "-m")
	out, err := cmd.Output()
	if err != nil {
		return "x86_64"
	}
	return strings.TrimSpace(string(out))
}

// Background Traffic Collector (samples every 3 seconds for the graph)
func startTrafficCollector() {
	_, lastIn, lastOut := getNetworkTraffic()
	for {
		time.Sleep(3 * time.Second)
		_, curIn, curOut := getNetworkTraffic()
		deltaIn := float64(curIn-lastIn) / 1024 / 1024 / 3.0   // MB/s
		deltaOut := float64(curOut-lastOut) / 1024 / 1024 / 3.0 // MB/s
		lastIn = curIn
		lastOut = curOut

		historyMu.Lock()
		trafficHistory = append(trafficHistory, TrafficRecord{
			Time: time.Now().Format("15:04:05"),
			Rx:   deltaIn,
			Tx:   deltaOut,
		})
		// Cap history at 20 records
		if len(trafficHistory) > 20 {
			trafficHistory = trafficHistory[1:]
		}
		historyMu.Unlock()
	}
}

// Subscription Endpoints
type ClashConfig struct {
	Port       int                      `yaml:"port"`
	SocksPort  int                      `yaml:"socks-port"`
	MixedPort  int                      `yaml:"mixed-port"`
	AllowLan   bool                     `yaml:"allow-lan"`
	Mode       string                   `yaml:"mode"`
	LogLevel   string                   `yaml:"log-level"`
	IPv6       bool                     `yaml:"ipv6"`
	DNS        ClashDNS                 `yaml:"dns"`
	Proxies    []map[string]interface{} `yaml:"proxies"`
	ProxyGroups []map[string]interface{} `yaml:"proxy-groups"`
	Rules      []string                 `yaml:"rules"`
}

type ClashDNS struct {
	Enable      bool     `yaml:"enable"`
	IPv6        bool     `yaml:"ipv6"`
	EnhancedMode string   `yaml:"enhanced-mode"`
	FakeIPRange string   `yaml:"fake-ip-range"`
	Nameserver  []string `yaml:"nameserver"`
}

func handleSubClash(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/sub/clash/")
	cfgMu.RLock()
	validToken := cfg.Token
	cfgMu.RUnlock()

	if token != validToken {
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	cfgMu.RLock()
	clash := ClashConfig{
		Port:      7890,
		SocksPort: 7891,
		MixedPort: 7893,
		AllowLan:  true,
		Mode:      "rule",
		LogLevel:  "info",
		IPv6:      false,
		DNS: ClashDNS{
			Enable:       true,
			IPv6:         false,
			EnhancedMode: "fake-ip",
			FakeIPRange:  "198.18.0.1/16",
			Nameserver: []string{
				"https://1.1.1.1/dns-query",
				"https://8.8.8.8/dns-query",
			},
		},
	}

	// Add Hysteria 2 proxy
	clash.Proxies = append(clash.Proxies, map[string]interface{}{
		"name":             "Hysteria 2",
		"type":             "hysteria2",
		"server":           cfg.Domain,
		"port":             cfg.HysteriaPort,
		"password":         cfg.HysteriaPassword,
		"sni":              cfg.Domain,
		"skip-cert-verify": cfg.SkipCertVerify,
	})

	// Add Mieru proxy
	clash.Proxies = append(clash.Proxies, map[string]interface{}{
		"name":     "Mieru",
		"type":     "mieru",
		"server":   cfg.Domain,
		"port":     cfg.MieruPort,
		"username": cfg.MieruUser,
		"password": cfg.MieruPassword,
	})

	// Add AnyTLS proxy
	clash.Proxies = append(clash.Proxies, map[string]interface{}{
		"name":             "AnyTLS",
		"type":             "anytls",
		"server":           cfg.Domain,
		"port":             cfg.AnyTLSPort,
		"password":         cfg.AnyTLSPassword,
		"sni":              cfg.Domain,
		"skip-cert-verify": true, // Reference anytls uses self-signed cert
	})

	clash.ProxyGroups = append(clash.ProxyGroups, map[string]interface{}{
		"name": "PROXY",
		"type": "select",
		"proxies": []string{
			"Hysteria 2",
			"Mieru",
			"AnyTLS",
		},
	})

	// Setup Direct Domains
	directDomains := strings.Split(cfg.DirectList, "\n")
	for _, domain := range directDomains {
		domain = strings.TrimSpace(domain)
		if domain != "" && !strings.HasPrefix(domain, "#") {
			clash.Rules = append(clash.Rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,DIRECT", domain))
		}
	}

	clash.Rules = append(clash.Rules, "GEOIP,RU,DIRECT")
	clash.Rules = append(clash.Rules, "MATCH,PROXY")
	cfgMu.RUnlock()

	out, err := yaml.Marshal(clash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Write(out)
}

func handleSubSingbox(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/sub/singbox/")
	cfgMu.RLock()
	validToken := cfg.Token
	cfgMu.RUnlock()

	if token != validToken {
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	cfgMu.RLock()
	singbox := map[string]interface{}{
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"tag": "cloudflare", "address": "https://1.1.1.1/dns-query"},
				{"tag": "local", "address": "local", "detour": "direct"},
			},
			"rules": []map[string]interface{}{
				{"outbound": "direct", "geoip": []string{"private"}},
			},
		},
		"inbounds": []map[string]interface{}{
			{"type": "mixed", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"outbounds": []map[string]interface{}{
			{
				"type":        "hysteria2",
				"tag":         "Hysteria 2",
				"server":      cfg.Domain,
				"server_port": cfg.HysteriaPort,
				"password":    cfg.HysteriaPassword,
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": cfg.Domain,
					"insecure":    cfg.SkipCertVerify,
				},
			},
			{
				"type":         "mieru",
				"tag":          "Mieru",
				"server":       cfg.Domain,
				"server_port":  cfg.MieruPort,
				"username":     cfg.MieruUser,
				"password":     cfg.MieruPassword,
				"multiplexing": true,
			},
			{
				"type":        "anytls",
				"tag":         "AnyTLS",
				"server":      cfg.Domain,
				"server_port": cfg.AnyTLSPort,
				"password":    cfg.AnyTLSPassword,
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": cfg.Domain,
					"insecure":    true,
				},
			},
			{
				"type":        "naive",
				"tag":         "NaiveProxy",
				"server":      cfg.Domain,
				"server_port": cfg.NaivePort,
				"username":    cfg.NaiveUser,
				"password":    cfg.NaivePassword,
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": cfg.Domain,
					"insecure":    cfg.SkipCertVerify,
				},
			},
			{
				"type": "direct",
				"tag":  "direct",
			},
		},
	}

	// Routing Rules
	var directDomains []string
	domains := strings.Split(cfg.DirectList, "\n")
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain != "" && !strings.HasPrefix(domain, "#") {
			directDomains = append(directDomains, domain)
		}
	}

	singbox["route"] = map[string]interface{}{
		"rules": []map[string]interface{}{
			{"domain_suffix": directDomains, "outbound": "direct"},
			{"geoip": []string{"ru"}, "outbound": "direct"},
			{"outbound": "Hysteria 2"}, // Default Proxy node
		},
	}
	cfgMu.RUnlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(singbox)
}
