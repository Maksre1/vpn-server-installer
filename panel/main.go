package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"sort"

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
	WarpMode         string `json:"warp_mode"`
	WarpRulesURL     string `json:"warp_rules_url"`
	DirectRulesURL   string `json:"direct_rules_url"`
	DNSProxy         string `json:"dns_proxy"`
	DNSDirect        string `json:"dns_direct"`
	CustomDNSProxy   string `json:"custom_dns_proxy"`
	CustomDNSDirect  string `json:"custom_dns_direct"`
	HysteriaSNI      string `json:"hysteria_sni"`
	AnyTLSSNI        string `json:"anytls_sni"`
	NaiveSNI         string `json:"naive_sni"`
	WarpLicenseKey   string `json:"warp_license_key"`
	AdminUser        string `json:"admin_user"`
	ProtonConfig     string          `json:"proton_config"`
	ProtonProfiles   []ProtonProfile `json:"proton_profiles"`
	ProtonStrategy   string          `json:"proton_strategy"`
	ProtonFallback   string          `json:"proton_fallback"`
	HysteriaCascade  string          `json:"hysteria_cascade"`
	MieruCascade     string          `json:"mieru_cascade"`
	AnyTLSCascade    string          `json:"anytls_cascade"`
	NaiveCascade     string          `json:"naive_cascade"`
	DomainRoutes     string          `json:"domain_routes"`
}


type ProtonProfile struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	PrivateKey string   `json:"private_key"`
	Addresses  []string `json:"addresses"`
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	Port       int      `json:"port"`
}

type SystemMetricRecord struct {
	Time string
	Rx   float64
	Tx   float64
	CPU  float64
	RAM  float64
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
	rateLimitMu    sync.Mutex
	metricsHistory []SystemMetricRecord
	historyMu      sync.Mutex
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
	CPURates []float64 `json:"CPURates"`
	RAMRates []float64 `json:"RAMRates"`
}

func main() {
	loadConfig()

	// Ensure subscriptions are pre-generated on startup
	go func() {
		time.Sleep(2 * time.Second)
		pregenerateSubscriptions()
	}()


	// Ensure config directory exists
	os.MkdirAll(filepath.Dir(configPath), 0755)

	// Create auth log file
	f, err := os.OpenFile(authLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		f.Close()
	}

	// Start traffic historical rate collector
	go startTrafficCollector()

	// Start background direct rules updater (Github/fallback sync)
	go startDirectRulesUpdater()
	go startWarpRulesUpdater()

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
	http.HandleFunc("/api/update-panel", handleUpdatePanel)
	http.HandleFunc("/api/protocol-settings", handleGetProtocolSettings)
	http.HandleFunc("/api/save-protocol-settings", handleSaveProtocolSettings)
	http.HandleFunc("/sub/clash/", handleSubClash)
	http.HandleFunc("/sub/singbox/", handleSubSingbox)
	http.HandleFunc("/sub/universal/", handleSubUniversal)
	http.HandleFunc("/", handleIndex)

	// Start HTTP listener for subscription endpoints on Port + 1 (to bypass self-signed cert errors in strict clients)
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/sub/clash/", handleSubClash)
		mux.HandleFunc("/sub/singbox/", handleSubSingbox)
		mux.HandleFunc("/sub/universal/", handleSubUniversal)
		// Redirect root to HTTPS UI
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, fmt.Sprintf("https://%s:%d/", cfg.Domain, cfg.Port), http.StatusFound)
		})
		log.Printf("HTTP Subscription server listening on :%d\n", cfg.Port+1)
		http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port+1), mux)
	}()

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

func parseMultipleWireGuardConfigs(configText string) []ProtonProfile {
	var profiles []ProtonProfile
	var currentBlock []string
	lines := strings.Split(configText, "\n")
	
	saveCurrentBlock := func() {
		if len(currentBlock) == 0 {
			return
		}
		privKey, addrs, pubKey, ep, port, name, err := parseSingleWireGuardConfig(strings.Join(currentBlock, "\n"))
		if err == nil {
			idx := len(profiles) + 1
			id := fmt.Sprintf("proton-%d", idx)
			if name == "" {
				name = fmt.Sprintf("Proton #%d (%s)", idx, ep)
			}
			profiles = append(profiles, ProtonProfile{
				ID:         id,
				Name:       name,
				PrivateKey: privKey,
				Addresses:  addrs,
				PublicKey:  pubKey,
				Endpoint:   ep,
				Port:       port,
			})
		}
		currentBlock = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "[interface]") {
			saveCurrentBlock()
		}
		currentBlock = append(currentBlock, line)
	}
	saveCurrentBlock()
	return profiles
}

func parseSingleWireGuardConfig(configText string) (privateKey string, addresses []string, publicKey string, endpoint string, port int, name string, err error) {
	lines := strings.Split(configText, "\n")
	var currentSection string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			comment := strings.TrimSpace(strings.TrimLeft(line, "#;"))
			commentLower := strings.ToLower(comment)
			if name == "" && comment != "" && !strings.Contains(commentLower, "protonvpn") && !strings.Contains(commentLower, "wireguard") && len(comment) < 40 {
				name = comment
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(line[1 : len(line)-1])
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		val := strings.TrimSpace(parts[1])

		if currentSection == "interface" {
			if key == "privatekey" {
				privateKey = val
			} else if key == "address" {
				addrParts := strings.Split(val, ",")
				for _, addr := range addrParts {
					addresses = append(addresses, strings.TrimSpace(addr))
				}
			}
		} else if currentSection == "peer" {
			if key == "publickey" {
				publicKey = val
			} else if key == "endpoint" {
				host, portStr, splitErr := net.SplitHostPort(val)
				if splitErr == nil {
					endpoint = host
					if p, errConv := strconv.Atoi(portStr); errConv == nil {
						port = p
					}
				} else {
					endpoint = val
					port = 51820
				}
			}
		}
	}
	if privateKey == "" || publicKey == "" || endpoint == "" || len(addresses) == 0 {
		return "", nil, "", "", 0, "", fmt.Errorf("invalid config")
	}
	return privateKey, addresses, publicKey, endpoint, port, name, nil
}

var (
	directDomainsFromGithub   []string
	directDomainsFromGithubMu sync.RWMutex
	directRulesCachePath      = "/etc/vpn-protocols/direct-rules-cache.json"
)

func loadDirectRulesCache() {
	directDomainsFromGithubMu.Lock()
	defer directDomainsFromGithubMu.Unlock()

	data, err := os.ReadFile(directRulesCachePath)
	if err != nil {
		fallbackData, errFallback := os.ReadFile("/opt/vpn-panel/lists/outside-clashx.yaml")
		if errFallback == nil {
			directDomainsFromGithub = parseClashRules(fallbackData)
			log.Printf("Loaded %d direct domains from fallback outside-clashx.yaml\n", len(directDomainsFromGithub))
		}
		return
	}
	if err := json.Unmarshal(data, &directDomainsFromGithub); err != nil {
		log.Println("Error unmarshaling direct rules cache:", err)
	} else {
		log.Printf("Loaded %d direct domains from cache\n", len(directDomainsFromGithub))
	}
}

func parseClashRules(data []byte) []string {
	var payload struct {
		Payload []string `yaml:"payload"`
	}
	if err := yaml.Unmarshal(data, &payload); err != nil {
		log.Println("Error parsing Clash rules YAML:", err)
		return nil
	}
	var domains []string
	for _, rule := range payload.Payload {
		parts := strings.Split(rule, ",")
		if len(parts) >= 2 {
			domain := strings.TrimSpace(parts[1])
			domain = strings.Trim(domain, `'"`)
			domains = append(domains, domain)
		}
	}
	return domains
}

func updateDirectRules() {
	cfgMu.RLock()
	url := cfg.DirectRulesURL
	cfgMu.RUnlock()

	if url == "" {
		url = "https://raw.githubusercontent.com/Maksre1/clash-rules/main/outside-clashx.yaml"
	}

	urls := strings.Split(url, ",")
	var mergedDomains []string
	client := &http.Client{Timeout: 10 * time.Second}
	downloadedAny := false

	for _, urlStr := range urls {
		urlStr = strings.TrimSpace(urlStr)
		if urlStr == "" {
			continue
		}
		log.Println("Fetching direct rules from URL:", urlStr)
		resp, err := client.Get(urlStr)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if bodyBytes, readErr := io.ReadAll(resp.Body); readErr == nil {
					domains := parseClashRules(bodyBytes)
					if len(domains) > 0 {
						mergedDomains = append(mergedDomains, domains...)
						downloadedAny = true
					}
				}
			}
		} else {
			log.Println("Failed to fetch direct rules from URL:", urlStr, err)
		}
	}

	if !downloadedAny {
		log.Println("Failed to fetch direct rules from GitHub, trying local fallback...")
		bodyBytes, errFallback := os.ReadFile("/opt/vpn-panel/lists/outside-clashx.yaml")
		if errFallback == nil {
			mergedDomains = parseClashRules(bodyBytes)
		} else {
			log.Println("Error reading fallback outside-clashx.yaml:", errFallback)
			return
		}
	}

	domains := uniqueStrings(mergedDomains)
	if len(domains) > 0 {
		directDomainsFromGithubMu.Lock()
		directDomainsFromGithub = domains
		directDomainsFromGithubMu.Unlock()

		cacheData, errMarshal := json.MarshalIndent(domains, "", "  ")
		if errMarshal == nil {
			os.WriteFile(directRulesCachePath, cacheData, 0644)
		}
		log.Printf("Successfully updated %d direct domains from GitHub/fallback\n", len(domains))

		go applyRoutingChanges()
	}
}

func startDirectRulesUpdater() {
	loadDirectRulesCache()
	go func() {
		time.Sleep(5 * time.Second)
		updateDirectRules()
	}()

	ticker := time.NewTicker(6 * time.Hour)
	go func() {
		for range ticker.C {
			updateDirectRules()
		}
	}()
}

func startWarpRulesUpdater() {
	ticker := time.NewTicker(12 * time.Hour)
	go func() {
		for range ticker.C {
			log.Println("Periodic 12-hour update of WARP domain lists starting...")
			applyRoutingChanges()
		}
	}()
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

	if cfg.WarpMode == "" {
		cfg.WarpMode = "global"
	}
	if cfg.DirectRulesURL == "" {
		cfg.DirectRulesURL = "https://raw.githubusercontent.com/Maksre1/clash-rules/main/outside-clashx.yaml"
	}
	if cfg.DNSProxy == "" {
		cfg.DNSProxy = "cloudflare"
	}
	if cfg.DNSDirect == "" {
		cfg.DNSDirect = "cloudflare"
	}
	if cfg.CertPath == "" {
		cfg.CertPath = "/etc/vpn-protocols/certs/cert.pem"
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = "/etc/vpn-protocols/certs/key.pem"
	}
	if cfg.AdminUser == "" {
		cfg.AdminUser = "admin"
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
		"ServerIP":        cfg.ServerIP,
		"Domain":          cfg.Domain,
		"Port":            cfg.Port,
		"HTTPPort":        cfg.Port + 1,
		"Token":           cfg.Token,
		"WarpGlobal":      cfg.WarpGlobal,
		"DirectList":      cfg.DirectList,
		"WarpList":        cfg.WarpList,
		"WarpMode":        cfg.WarpMode,
		"WarpRulesURL":    cfg.WarpRulesURL,
		"DirectRulesURL":  cfg.DirectRulesURL,
		"DNSProxy":        cfg.DNSProxy,
		"DNSDirect":       cfg.DNSDirect,
		"CustomDNSProxy":  cfg.CustomDNSProxy,
		"CustomDNSDirect": cfg.CustomDNSDirect,
		"WarpLicenseKey":  cfg.WarpLicenseKey,
		"AdminUser":       cfg.AdminUser,
		"CertPath":        cfg.CertPath,
		"KeyPath":         cfg.KeyPath,
		"SkipCertVerify":  cfg.SkipCertVerify,
		"ProtonConfig":    cfg.ProtonConfig,
		"ProtonProfiles":  cfg.ProtonProfiles,
		"ProtonStrategy":  cfg.ProtonStrategy,
		"ProtonFallback":  cfg.ProtonFallback,
		"HysteriaCascade": cfg.HysteriaCascade,
		"MieruCascade":     cfg.MieruCascade,
		"AnyTLSCascade":    cfg.AnyTLSCascade,
		"NaiveCascade":     cfg.NaiveCascade,
		"DomainRoutes":    cfg.DomainRoutes,
		"Virt":            getVirtualization(),
		"Arch":            getArchitecture(),
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
	expectedUser := cfg.AdminUser
	if expectedUser == "" {
		expectedUser = "admin"
	}
	expectedHash := cfg.PasswordHash
	cfgMu.RUnlock()

	err := bcrypt.CompareHashAndPassword([]byte(expectedHash), []byte(password))
	if username == expectedUser && err == nil {
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
	if !checkSession(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

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
	adminUser := r.FormValue("admin_user")

	cfgMu.RLock()
	expectedHash := cfg.PasswordHash
	cfgMu.RUnlock()

	err := bcrypt.CompareHashAndPassword([]byte(expectedHash), []byte(oldPass))
	if err != nil {
		http.Error(w, "Неверный текущий пароль", http.StatusForbidden)
		return
	}

	cfgMu.Lock()
	if adminUser != "" {
		cfg.AdminUser = adminUser
	}
	if newPass != "" {
		if len(newPass) < 8 {
			cfgMu.Unlock()
			http.Error(w, "Пароль слишком короткий (минимум 8 символов)", http.StatusBadRequest)
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		cfg.PasswordHash = string(hash)
	}
	cfgMu.Unlock()

	saveConfig()
	logAuthEvent(ip, "admin", "CREDENTIALS_CHANGED")
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if !checkSession(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	cfgMu.Lock()
	if r.Form["warp_global"] != nil {
		cfg.WarpGlobal = r.FormValue("warp_global") == "on"
	}
	if r.Form["direct_list"] != nil {
		cfg.DirectList = r.FormValue("direct_list")
	}
	if r.Form["warp_list"] != nil {
		cfg.WarpList = r.FormValue("warp_list")
	}
	if r.Form["warp_mode"] != nil {
		cfg.WarpMode = r.FormValue("warp_mode")
	}
	if r.Form["warp_rules_url"] != nil {
		cfg.WarpRulesURL = r.FormValue("warp_rules_url")
	}
	if r.Form["direct_rules_url"] != nil {
		cfg.DirectRulesURL = r.FormValue("direct_rules_url")
	}
	if r.Form["dns_proxy"] != nil {
		cfg.DNSProxy = r.FormValue("dns_proxy")
	}
	if r.Form["dns_direct"] != nil {
		cfg.DNSDirect = r.FormValue("dns_direct")
	}
	if r.Form["custom_dns_proxy"] != nil {
		cfg.CustomDNSProxy = r.FormValue("custom_dns_proxy")
	}
	if r.Form["custom_dns_direct"] != nil {
		cfg.CustomDNSDirect = r.FormValue("custom_dns_direct")
	}
	if r.Form["proton_config"] != nil {
		protonConfig := r.FormValue("proton_config")
		cfg.ProtonConfig = protonConfig
		cfg.ProtonProfiles = parseMultipleWireGuardConfigs(protonConfig)
	}
	if r.Form["proton_strategy"] != nil {
		cfg.ProtonStrategy = r.FormValue("proton_strategy")
	}
	if r.Form["proton_fallback"] != nil {
		cfg.ProtonFallback = r.FormValue("proton_fallback")
	}
	if r.Form["hysteria_cascade"] != nil {
		cfg.HysteriaCascade = r.FormValue("hysteria_cascade")
	}
	if r.Form["mieru_cascade"] != nil {
		cfg.MieruCascade = r.FormValue("mieru_cascade")
	}
	if r.Form["anytls_cascade"] != nil {
		cfg.AnyTLSCascade = r.FormValue("anytls_cascade")
	}
	if r.Form["naive_cascade"] != nil {
		cfg.NaiveCascade = r.FormValue("naive_cascade")
	}
	if r.Form["domain_routes"] != nil {
		cfg.DomainRoutes = r.FormValue("domain_routes")
	}

	domainChanged := false
	certPathsChanged := false

	if r.Form["domain"] != nil {
		domain := r.FormValue("domain")
		if domain != "" && cfg.Domain != domain {
			cfg.Domain = domain
			domainChanged = true
		}
	}
	if r.Form["admin_user"] != nil {
		adminUser := r.FormValue("admin_user")
		if adminUser != "" {
			cfg.AdminUser = adminUser
		}
	}
	if r.Form["cert_path"] != nil || r.Form["key_path"] != nil {
		certPath := r.FormValue("cert_path")
		keyPath := r.FormValue("key_path")
		if certPath != "" && keyPath != "" && (cfg.CertPath != certPath || cfg.KeyPath != keyPath) {
			cfg.CertPath = certPath
			cfg.KeyPath = keyPath
			certPathsChanged = true
		}
	}
	if r.Form["skip_cert_verify"] != nil {
		cfg.SkipCertVerify = r.FormValue("skip_cert_verify") == "on"
	} else {
		if r.Form["domain"] != nil || r.Form["cert_path"] != nil {
			cfg.SkipCertVerify = false
		}
	}
	cfgMu.Unlock()

	saveConfig()

	if certPathsChanged || domainChanged {
		log.Println("SSL / Domain settings changed, recreating configs...")
		cfgMu.RLock()
		hyContent := fmt.Sprintf("listen: :%d\ntls:\n  cert: %s\n  key: %s\nauth:\n  type: password\n  password: \"%s\"\n", cfg.HysteriaPort, cfg.CertPath, cfg.KeyPath, cfg.HysteriaPassword)
		os.WriteFile("/etc/vpn-protocols/hysteria2.yaml", []byte(hyContent), 0644)
		go exec.Command("systemctl", "restart", "hysteria2").Run()

		caddyContent := fmt.Sprintf(`:%d {
    tls "%s" "%s"
    forward_proxy {
        basic_auth "%s" "%s"
        hide_ip
        hide_via
        probe_resistance
    }
}
`, cfg.NaivePort, cfg.CertPath, cfg.KeyPath, cfg.NaiveUser, cfg.NaivePassword)
		os.WriteFile("/etc/vpn-protocols/Caddyfile", []byte(caddyContent), 0644)
		go exec.Command("systemctl", "restart", "caddy").Run()
		cfgMu.RUnlock()
	}

	go applyRoutingChanges()

	http.Redirect(w, r, "/", http.StatusFound)
}

func applyRoutingChanges() {
	log.Println("Applying routing changes natively...")
	if err := generateSingboxServerConfig(); err != nil {
		log.Println("Error generating singbox-server config:", err)
	}

	// Restart singbox-server via systemctl
	cmd := exec.Command("systemctl", "restart", "singbox-server")
	if err := cmd.Run(); err != nil {
		log.Println("Error restarting singbox-server service:", err)
	} else {
		log.Println("Restarted singbox-server successfully")
	}

	// Pregenerate static subscriptions
	if err := pregenerateSubscriptions(); err != nil {
		log.Println("Error pregenerating subscriptions:", err)
	}
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
	var cpuRates []float64
	var ramRates []float64
	for _, rec := range metricsHistory {
		labels = append(labels, rec.Time)
		inRates = append(inRates, rec.Rx)
		outRates = append(outRates, rec.Tx)
		cpuRates = append(cpuRates, rec.CPU)
		ramRates = append(ramRates, rec.RAM)
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
			CPURates: cpuRates,
			RAMRates: ramRates,
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
	// Check if warp-credentials.json exists
	if _, err := os.Stat("/etc/vpn-protocols/warp-credentials.json"); err != nil {
		return WarpInfo{Active: false}
	}

	// Check if singbox-server is running
	cmd := exec.Command("systemctl", "is-active", "--quiet", "singbox-server")
	if err := cmd.Run(); err != nil {
		return WarpInfo{Active: false}
	}

	// Fetch WARP IP and test latency via Cloudflare Trace
	client := http.Client{Timeout: 1200 * time.Millisecond}
	start := time.Now()
	resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	latency := int(time.Since(start).Milliseconds())

	if err != nil {
		return WarpInfo{Active: true, IP: "Активен (Сплит)", Latency: 0}
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

	if warpStatus == "on" {
		return WarpInfo{Active: true, IP: ip, Latency: latency}
	}
	return WarpInfo{Active: true, IP: "Обход (" + ip + ")", Latency: latency}
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

		cpuPercent := getCPUUsage()
		_, _, ramPercent := getRAMUsage()

		historyMu.Lock()
		metricsHistory = append(metricsHistory, SystemMetricRecord{
			Time: time.Now().Format("15:04:05"),
			Rx:   deltaIn,
			Tx:   deltaOut,
			CPU:  cpuPercent,
			RAM:  ramPercent,
		})
		// Cap history at 20 records
		if len(metricsHistory) > 20 {
			metricsHistory = metricsHistory[1:]
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

func getDNSAddress(dnsType, customValue string) string {
	switch dnsType {
	case "cloudflare":
		return "https://1.1.1.1/dns-query"
	case "google":
		return "https://8.8.8.8/dns-query"
	case "adguard":
		return "https://dns.adguard-dns.com/dns-query"
	case "custom":
		if customValue != "" {
			return customValue
		}
	}
	return "https://1.1.1.1/dns-query"
}

func buildClashSubscription() ([]byte, error) {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

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
				getDNSAddress(cfg.DNSProxy, cfg.CustomDNSProxy),
			},
		},
	}

	hy2SNI := cfg.HysteriaSNI
	if hy2SNI == "" {
		hy2SNI = cfg.Domain
		if cfg.SkipCertVerify {
			hy2SNI = "dl.google.com"
		}
	}

	clash.Proxies = append(clash.Proxies, map[string]interface{}{
		"name":             "Hysteria 2",
		"type":             "hysteria2",
		"server":           cfg.Domain,
		"port":             cfg.HysteriaPort,
		"password":         cfg.HysteriaPassword,
		"sni":              hy2SNI,
		"skip-cert-verify": cfg.SkipCertVerify,
	})

	clash.Proxies = append(clash.Proxies, map[string]interface{}{
		"name":         "Mieru",
		"type":         "mieru",
		"server":       cfg.Domain,
		"port":         cfg.MieruPort,
		"username":     cfg.MieruUser,
		"password":     cfg.MieruPassword,
		"transport":    "TCP",
		"udp":          true,
		"multiplexing": "MULTIPLEXING_HIGH",
	})

	anytlsSNI := cfg.AnyTLSSNI
	if anytlsSNI == "" {
		anytlsSNI = "images.apple.com"
	}

	clash.Proxies = append(clash.Proxies, map[string]interface{}{
		"name":               "AnyTLS",
		"type":               "anytls",
		"server":             cfg.Domain,
		"port":               cfg.AnyTLSPort,
		"password":           cfg.AnyTLSPassword,
		"sni":                anytlsSNI,
		"client-fingerprint": "chrome",
		"udp":                true,
		"alpn":               []string{"h2", "http/1.1"},
		"skip-cert-verify":   true,
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

	directDomains := strings.Split(cfg.DirectList, "\n")
	for _, domain := range directDomains {
		domain = strings.TrimSpace(domain)
		if domain != "" && !strings.HasPrefix(domain, "#") {
			clash.Rules = append(clash.Rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,DIRECT", domain))
		}
	}

	directDomainsFromGithubMu.RLock()
	for _, domain := range directDomainsFromGithub {
		clash.Rules = append(clash.Rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,DIRECT", domain))
	}
	directDomainsFromGithubMu.RUnlock()

	clash.Rules = append(clash.Rules, "GEOIP,RU,DIRECT")
	clash.Rules = append(clash.Rules, "MATCH,PROXY")

	return yaml.Marshal(clash)
}

func buildSingboxSubscription() ([]byte, error) {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	hy2SNI := cfg.HysteriaSNI
	if hy2SNI == "" {
		hy2SNI = cfg.Domain
		if cfg.SkipCertVerify {
			hy2SNI = "dl.google.com"
		}
	}

	anytlsSNI := cfg.AnyTLSSNI
	if anytlsSNI == "" {
		anytlsSNI = "images.apple.com"
	}

	naiveSNI := cfg.NaiveSNI
	if naiveSNI == "" {
		naiveSNI = cfg.Domain
	}

	singbox := map[string]interface{}{
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"tag": "proxy-dns", "address": getDNSAddress(cfg.DNSProxy, cfg.CustomDNSProxy)},
				{"tag": "local", "address": getDNSAddress(cfg.DNSDirect, cfg.CustomDNSDirect), "detour": "direct"},
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
					"server_name": hy2SNI,
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
					"server_name": anytlsSNI,
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
					"server_name": naiveSNI,
					"insecure":    cfg.SkipCertVerify,
				},
			},
			{
				"type": "direct",
				"tag":  "direct",
			},
		},
	}

	var directDomains []string
	domains := strings.Split(cfg.DirectList, "\n")
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain != "" && !strings.HasPrefix(domain, "#") {
			directDomains = append(directDomains, domain)
		}
	}

	directDomainsFromGithubMu.RLock()
	for _, domain := range directDomainsFromGithub {
		directDomains = append(directDomains, domain)
	}
	directDomainsFromGithubMu.RUnlock()

	singbox["route"] = map[string]interface{}{
		"rules": []map[string]interface{}{
			{"domain_suffix": directDomains, "outbound": "direct"},
			{"geoip": []string{"ru"}, "outbound": "direct"},
			{"outbound": "Hysteria 2"},
		},
	}

	return json.MarshalIndent(singbox, "", "  ")
}

func buildUniversalSubscription() ([]byte, error) {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	insecureStr := "0"
	if cfg.SkipCertVerify {
		insecureStr = "1"
	}

	hy2URI := fmt.Sprintf("hysteria2://%s@%s:%d/?insecure=%s&sni=%s#Hysteria2",
		cfg.HysteriaPassword, cfg.Domain, cfg.HysteriaPort, insecureStr, cfg.Domain)

	payload := hy2URI + "\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	return []byte(b64), nil
}

func pregenerateSubscriptions() error {
	cfgMu.RLock()
	token := cfg.Token
	cfgMu.RUnlock()

	if token == "" {
		return fmt.Errorf("token is empty")
	}

	subsDir := "/etc/vpn-protocols/subs"
	os.MkdirAll(subsDir, 0755)

	clashBytes, err := buildClashSubscription()
	if err == nil {
		os.WriteFile(filepath.Join(subsDir, "clash_"+token+".yaml"), clashBytes, 0644)
	} else {
		log.Println("Error building Clash sub:", err)
	}

	singboxBytes, err := buildSingboxSubscription()
	if err == nil {
		os.WriteFile(filepath.Join(subsDir, "singbox_"+token+".json"), singboxBytes, 0644)
	} else {
		log.Println("Error building Sing-box sub:", err)
	}

	universalBytes, err := buildUniversalSubscription()
	if err == nil {
		os.WriteFile(filepath.Join(subsDir, "universal_"+token+".txt"), universalBytes, 0644)
	} else {
		log.Println("Error building Universal sub:", err)
	}

	log.Println("Pregenerated static subscription files successfully")
	return nil
}

func handleSubClash(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/sub/clash/")
	token = strings.TrimSuffix(token, ".yaml")
	cfgMu.RLock()
	validToken := cfg.Token
	cfgMu.RUnlock()

	if token != validToken {
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	subsDir := "/etc/vpn-protocols/subs"
	filePath := filepath.Join(subsDir, "clash_"+token+".yaml")

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Println("Sub cache miss for Clash, generating on the fly")
		var buildErr error
		data, buildErr = buildClashSubscription()
		if buildErr != nil {
			http.Error(w, buildErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Write(data)
}

func handleSubSingbox(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/sub/singbox/")
	token = strings.TrimSuffix(token, ".json")
	cfgMu.RLock()
	validToken := cfg.Token
	cfgMu.RUnlock()

	if token != validToken {
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	subsDir := "/etc/vpn-protocols/subs"
	filePath := filepath.Join(subsDir, "singbox_"+token+".json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Println("Sub cache miss for Sing-box, generating on the fly")
		var buildErr error
		data, buildErr = buildSingboxSubscription()
		if buildErr != nil {
			http.Error(w, buildErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(data)
}

func handleSubUniversal(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/sub/universal/")
	token = strings.TrimSuffix(token, ".txt")
	cfgMu.RLock()
	validToken := cfg.Token
	cfgMu.RUnlock()

	if token != validToken {
		http.Error(w, "Invalid Token", http.StatusForbidden)
		return
	}

	subsDir := "/etc/vpn-protocols/subs"
	filePath := filepath.Join(subsDir, "universal_"+token+".txt")

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Println("Sub cache miss for Universal, generating on the fly")
		var buildErr error
		data, buildErr = buildUniversalSubscription()
		if buildErr != nil {
			http.Error(w, buildErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

func uniqueStrings(input []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range input {
		if _, value := keys[entry]; !value && entry != "" {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func generateSingboxServerConfig() error {
	cfgMu.RLock()
	warpMode := cfg.WarpMode
	warpRulesURL := cfg.WarpRulesURL
	directList := cfg.DirectList
	warpList := cfg.WarpList
	panelPort := cfg.Port
	dnsProxy := cfg.DNSProxy
	dnsDirect := cfg.DNSDirect
	customDNSProxy := cfg.CustomDNSProxy
	customDNSDirect := cfg.CustomDNSDirect
	protonProfiles := cfg.ProtonProfiles
	protonStrategy := cfg.ProtonStrategy
	protonFallback := cfg.ProtonFallback
	hyCascade := cfg.HysteriaCascade
	mieCascade := cfg.MieruCascade
	anyCascade := cfg.AnyTLSCascade
	navCascade := cfg.NaiveCascade
	cfgMu.RUnlock()

	if warpMode == "" {
		warpMode = "global"
	}

	getDNSAddr := func(dnsType, customVal string) string {
		switch dnsType {
		case "cloudflare":
			return "https://1.1.1.1/dns-query"
		case "google":
			return "https://8.8.8.8/dns-query"
		case "adguard":
			return "https://dns.adguard-dns.com/dns-query"
		case "custom":
			if customVal != "" {
				return customVal
			}
		}
		return "https://1.1.1.1/dns-query"
	}
	dnsProxyAddr := getDNSAddr(dnsProxy, customDNSProxy)
	dnsDirectAddr := getDNSAddr(dnsDirect, customDNSDirect)

	hasWarp := false
	warpIpV4 := "172.16.0.2/32"
	warpIpV6 := "2606:4700:110::/128"
	warpPrivKey := ""
	warpReserved := []int{0, 0, 0}

	warpCredsPath := "/etc/vpn-protocols/warp-credentials.json"
	if data, err := os.ReadFile(warpCredsPath); err == nil {
		var creds struct {
			LocalAddressV4 string `json:"local_address_v4"`
			LocalAddressV6 string `json:"local_address_v6"`
			PrivateKey     string `json:"private_key"`
			Reserved       []int  `json:"reserved"`
		}
		if err := json.Unmarshal(data, &creds); err == nil {
			hasWarp = true
			warpIpV4 = creds.LocalAddressV4
			warpIpV6 = creds.LocalAddressV6
			warpPrivKey = creds.PrivateKey
			if len(creds.Reserved) == 3 {
				warpReserved = creds.Reserved
			}
		}
	}

	var directDomains []string
	lines := strings.Split(directList, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			directDomains = append(directDomains, line)
		}
	}

	directDomainsFromGithubMu.RLock()
	for _, domain := range directDomainsFromGithub {
		directDomains = append(directDomains, domain)
	}
	directDomainsFromGithubMu.RUnlock()
	directDomains = uniqueStrings(directDomains)

	var warpDomains []string
	warpLines := strings.Split(warpList, "\n")
	for _, line := range warpLines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			warpDomains = append(warpDomains, line)
		}
	}

	if warpMode == "domains" && warpRulesURL != "" {
		urls := strings.Split(warpRulesURL, ",")
		client := &http.Client{Timeout: 10 * time.Second}
		for _, urlStr := range urls {
			urlStr = strings.TrimSpace(urlStr)
			if urlStr == "" {
				continue
			}
			log.Println("Downloading WARP domains list from URL:", urlStr)
			if resp, err := client.Get(urlStr); err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					if body, err := io.ReadAll(resp.Body); err == nil {
						downloadedLines := strings.Split(string(body), "\n")
						for _, line := range downloadedLines {
							line = strings.TrimSpace(line)
							if line != "" && !strings.HasPrefix(line, "#") {
								warpDomains = append(warpDomains, line)
							}
						}
					}
				}
			} else {
				log.Println("Failed to download WARP domains from URL:", urlStr, err)
			}
		}
	}
	warpDomains = uniqueStrings(warpDomains)

	type SingBoxLog struct {
		Level  string `json:"level"`
		Output string `json:"output"`
	}
	type SingBoxDNSServer struct {
		Tag     string `json:"tag"`
		Address string `json:"address"`
		Detour  string `json:"detour,omitempty"`
	}
	type SingBoxDNSRule struct {
		Server       string   `json:"server"`
		DomainSuffix []string `json:"domain_suffix"`
	}
	type SingBoxDNS struct {
		Servers []SingBoxDNSServer `json:"servers"`
		Rules   []SingBoxDNSRule   `json:"rules"`
	}
	type SingBoxInbound struct {
		Type          string   `json:"type"`
		Tag           string   `json:"tag"`
		InterfaceName string   `json:"interface_name"`
		Address       []string `json:"address"`
		AutoRoute     bool     `json:"auto_route"`
		StrictRoute   bool     `json:"strict_route"`
		Stack         string   `json:"stack"`
	}
	type SingBoxPeer struct {
		Address    string   `json:"address"`
		Port       int      `json:"port"`
		PublicKey  string   `json:"public_key"`
		AllowedIPs []string `json:"allowed_ips"`
		Reserved   []int    `json:"reserved,omitempty"`
	}
	type SingBoxEndpoint struct {
		Type       string        `json:"type"`
		Tag        string        `json:"tag"`
		Address    []string      `json:"address"`
		PrivateKey string        `json:"private_key"`
		Mtu        int           `json:"mtu"`
		Peers      []SingBoxPeer `json:"peers"`
	}
	type SingBoxRouteRule struct {
		Port         int      `json:"port,omitempty"`
		DomainSuffix []string `json:"domain_suffix,omitempty"`
		ProcessName  []string `json:"process_name,omitempty"`
		Outbound     string   `json:"outbound"`
	}
	type SingBoxRoute struct {
		AutoDetectInterface bool               `json:"auto_detect_interface"`
		Rules               []SingBoxRouteRule `json:"rules"`
	}
	type SingBoxServerConfig struct {
		Log       SingBoxLog        `json:"log"`
		DNS       SingBoxDNS        `json:"dns"`
		Inbounds  []SingBoxInbound  `json:"inbounds"`
		Endpoints []SingBoxEndpoint `json:"endpoints,omitempty"`
		Outbounds []interface{}     `json:"outbounds"`
		Route     SingBoxRoute      `json:"route"`
	}

	serverCfg := SingBoxServerConfig{
		Log: SingBoxLog{
			Level:  "info",
			Output: "/var/log/singbox-server.log",
		},
		DNS: SingBoxDNS{
			Servers: []SingBoxDNSServer{
				{Tag: "proxy-dns", Address: dnsProxyAddr},
				{Tag: "proxy-dns", Address: "https://8.8.8.8/dns-query"},
				{Tag: "local", Address: dnsDirectAddr, Detour: "direct"},
				{Tag: "local", Address: "https://8.8.8.8/dns-query", Detour: "direct"},
			},
			Rules: []SingBoxDNSRule{
				{
					Server: "local",
					DomainSuffix: []string{
						"sslip.io",
						"nip.io",
						"traefik.me",
					},
				},
			},
		},
		Inbounds: []SingBoxInbound{
			{
				Type:          "tun",
				Tag:           "tun-in",
				InterfaceName: "singtun0",
				Address: []string{
					"172.19.0.1/30",
					"fdfe:dcba:9876::1/126",
				},
				AutoRoute:   true,
				StrictRoute: true,
				Stack:       "gvisor",
			},
		},
	}

	// 1. Add Endpoints (WireGuard interfaces)
	var endpoints []SingBoxEndpoint
	if hasWarp {
		endpoints = append(endpoints, SingBoxEndpoint{
			Type:       "wireguard",
			Tag:        "warp",
			Address:    []string{warpIpV4, warpIpV6},
			PrivateKey: warpPrivKey,
			Mtu:        1280,
			Peers: []SingBoxPeer{
				{
					Address:    "engage.cloudflareclient.com",
					Port:       2408,
					PublicKey:  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
					AllowedIPs: []string{"0.0.0.0/0", "::/0"},
					Reserved:   warpReserved,
				},
			},
		})
	}

	for _, profile := range protonProfiles {
		endpoints = append(endpoints, SingBoxEndpoint{
			Type:       "wireguard",
			Tag:        profile.ID,
			Address:    profile.Addresses,
			PrivateKey: profile.PrivateKey,
			Mtu:        1400,
			Peers: []SingBoxPeer{
				{
					Address:    profile.Endpoint,
					Port:       profile.Port,
					PublicKey:  profile.PublicKey,
					AllowedIPs: []string{"0.0.0.0/0", "::/0"},
				},
			},
		})
	}
	serverCfg.Endpoints = endpoints

	// 2. Add Outbounds
	outbounds := []interface{}{
		map[string]interface{}{
			"type": "direct",
			"tag":  "direct",
		},
	}

	fallbackOutbound := "direct"
	if protonFallback == "warp" && hasWarp {
		fallbackOutbound = "warp"
	}

	if len(protonProfiles) > 0 {
		var outbTags []string
		for _, p := range protonProfiles {
			outbTags = append(outbTags, p.ID)
		}

		// Group for Auto (fastest/failover)
		autoStrategy := "urltest"
		if protonStrategy == "failover" {
			autoStrategy = "failover"
		}

		if autoStrategy == "urltest" {
			outbounds = append(outbounds, map[string]interface{}{
				"type":      "urltest",
				"tag":       "proton-auto",
				"outbounds": outbTags,
				"url":       "https://www.google.com/generate_204",
				"interval":  "3m",
				"tolerance": 50,
			})
		} else {
			outbounds = append(outbounds, map[string]interface{}{
				"type":      "failover",
				"tag":       "proton-auto",
				"outbounds": outbTags,
			})
		}

		// Cascade failover group for auto-route
		outbounds = append(outbounds, map[string]interface{}{
			"type":      "failover",
			"tag":       "proton-cascade",
			"outbounds": []string{"proton-auto", fallbackOutbound},
		})

		// Cascade failover groups for specific servers
		for _, p := range protonProfiles {
			outbounds = append(outbounds, map[string]interface{}{
				"type":      "failover",
				"tag":       p.ID + "-cascade",
				"outbounds": []string{p.ID, fallbackOutbound},
			})
		}
	}
	serverCfg.Outbounds = outbounds

	getOutboundTag := func(cascade string) string {
		if cascade == "" || cascade == "warp" {
			if hasWarp {
				return "warp"
			}
			return "direct"
		}
		if cascade == "direct" {
			return "direct"
		}
		if cascade == "proton-auto" {
			if len(protonProfiles) > 0 {
				return "proton-cascade"
			}
			if hasWarp {
				return "warp"
			}
			return "direct"
		}
		if strings.HasPrefix(cascade, "proton-") {
			if len(protonProfiles) > 0 {
				return cascade + "-cascade"
			}
			if hasWarp {
				return "warp"
			}
			return "direct"
		}
		return "direct"
	}

	defaultOutbound := "direct"
	if warpMode == "global" || warpMode == "warp" {
		if hasWarp {
			defaultOutbound = "warp"
		}
	} else if warpMode != "" && warpMode != "direct" && warpMode != "domains" {
		defaultOutbound = getOutboundTag(warpMode)
	}

	rules := []SingBoxRouteRule{
		{Port: 22, Outbound: "direct"},
		{Port: panelPort, Outbound: "direct"},
	}

	// 3. Process-based Cascade Routing Rules
	if hyCascade != "direct" {
		rules = append(rules, SingBoxRouteRule{
			ProcessName: []string{"hysteria"},
			Outbound:    getOutboundTag(hyCascade),
		})
	}
	if mieCascade != "direct" {
		rules = append(rules, SingBoxRouteRule{
			ProcessName: []string{"mita"},
			Outbound:    getOutboundTag(mieCascade),
		})
	}
	if anyCascade != "direct" {
		rules = append(rules, SingBoxRouteRule{
			ProcessName: []string{"anytls-server"},
			Outbound:    getOutboundTag(anyCascade),
		})
	}
	if navCascade != "direct" {
		rules = append(rules, SingBoxRouteRule{
			ProcessName: []string{"caddy"},
			Outbound:    getOutboundTag(navCascade),
		})
	}

	// 4. Custom Domain Routes
	customDomainRoutes := make(map[string][]string)
	for _, line := range strings.Split(cfg.DomainRoutes, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			domain := strings.TrimSpace(parts[0])
			outbound := strings.TrimSpace(parts[1])
			if domain != "" && outbound != "" {
				customDomainRoutes[outbound] = append(customDomainRoutes[outbound], domain)
			}
		}
	}
	var outboundsWithRules []string
	for k := range customDomainRoutes {
		outboundsWithRules = append(outboundsWithRules, k)
	}
	sort.Strings(outboundsWithRules)
	for _, outb := range outboundsWithRules {
		doms := customDomainRoutes[outb]
		if len(doms) > 0 {
			rules = append(rules, SingBoxRouteRule{
				DomainSuffix: doms,
				Outbound:     getOutboundTag(outb),
			})
		}
	}

	if len(directDomains) > 0 {
		rules = append(rules, SingBoxRouteRule{
			DomainSuffix: directDomains,
			Outbound:     "direct",
		})
	}

	if hasWarp && len(warpDomains) > 0 {
		rules = append(rules, SingBoxRouteRule{
			DomainSuffix: warpDomains,
			Outbound:     "warp",
		})
	}

	rules = append(rules, SingBoxRouteRule{
		Outbound: defaultOutbound,
	})

	serverCfg.Route = SingBoxRoute{
		AutoDetectInterface: true,
		Rules:               rules,
	}

	configBytes, err := json.MarshalIndent(serverCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}

	configFilePath := "/etc/vpn-protocols/singbox-server.json"
	if err := os.WriteFile(configFilePath, configBytes, 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	log.Println("Generated singbox-server.json natively from Go")
	return nil
}

func handleUpdatePanel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkSession(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		log.Println("Triggering self-update script...")
		// Execute update.sh script on the server
		cmd := exec.Command("/bin/bash", "/root/vpn-server-installer/panel/update.sh")
		if err := cmd.Run(); err != nil {
			log.Println("Self-update script execution failed:", err)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Update initiated"))
}

type ProtocolSettingsRequest struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	SNI      string `json:"sni"`
}

func handleSaveProtocolSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkSession(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req ProtocolSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if req.Protocol != "WARP" && (req.Port <= 0 || req.Port > 65535) {
		http.Error(w, "Invalid Port", http.StatusBadRequest)
		return
	}

	cfgMu.Lock()
	var oldPort int
	switch req.Protocol {
	case "Hysteria2":
		oldPort = cfg.HysteriaPort
		cfg.HysteriaPort = req.Port
		cfg.HysteriaPassword = req.Password
		cfg.HysteriaSNI = req.SNI

		// Generate configuration
		confContent := fmt.Sprintf("listen: :%d\ntls:\n  cert: /etc/vpn-protocols/certs/cert.pem\n  key: /etc/vpn-protocols/certs/key.pem\nauth:\n  type: password\n  password: \"%s\"\n", req.Port, req.Password)
		if err := os.WriteFile("/etc/vpn-protocols/hysteria2.yaml", []byte(confContent), 0644); err != nil {
			log.Println("Error writing Hysteria2 config:", err)
		}
		go exec.Command("systemctl", "restart", "hysteria2").Run()

	case "Mieru":
		oldPort = cfg.MieruPort
		cfg.MieruPort = req.Port
		cfg.MieruUser = req.Username
		cfg.MieruPassword = req.Password

		type PortBinding struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		}
		type MieruUserObj struct {
			Name            string `json:"name"`
			Password        string `json:"password"`
			AllowPrivateIP  bool   `json:"allowPrivateIP"`
			AllowLoopbackIP bool   `json:"allowLoopbackIP"`
		}
		type MitaConfig struct {
			PortBindings []PortBinding  `json:"portBindings"`
			Users        []MieruUserObj `json:"users"`
			LoggingLevel string         `json:"loggingLevel"`
			Mtu          int            `json:"mtu"`
		}
		mitaCfg := MitaConfig{
			PortBindings: []PortBinding{
				{Port: req.Port, Protocol: "TCP"},
				{Port: req.Port, Protocol: "UDP"},
			},
			Users: []MieruUserObj{
				{Name: req.Username, Password: req.Password, AllowPrivateIP: true, AllowLoopbackIP: true},
			},
			LoggingLevel: "INFO",
			Mtu:          1400,
		}
		mitaBytes, err := json.MarshalIndent(mitaCfg, "", "  ")
		if err == nil {
			mitaConfPath := "/etc/vpn-protocols/mita.json"
			os.WriteFile(mitaConfPath, mitaBytes, 0644)
			exec.Command("/usr/local/bin/mita", "apply", "config", mitaConfPath).Run()
		} else {
			log.Println("Error marshaling Mieru config:", err)
		}
		go exec.Command("systemctl", "restart", "mita").Run()

	case "AnyTLS":
		oldPort = cfg.AnyTLSPort
		cfg.AnyTLSPort = req.Port
		cfg.AnyTLSPassword = req.Password
		cfg.AnyTLSSNI = req.SNI

		serviceContent := fmt.Sprintf(`[Unit]
Description=AnyTLS Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/anytls-server -l 0.0.0.0:%d -p %s
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, req.Port, req.Password)
		if err := os.WriteFile("/etc/systemd/system/anytls-server.service", []byte(serviceContent), 0644); err == nil {
			exec.Command("systemctl", "daemon-reload").Run()
		} else {
			log.Println("Error writing AnyTLS service file:", err)
		}
		go exec.Command("systemctl", "restart", "anytls-server").Run()

	case "NaiveProxy":
		oldPort = cfg.NaivePort
		cfg.NaivePort = req.Port
		cfg.NaiveUser = req.Username
		cfg.NaivePassword = req.Password
		cfg.NaiveSNI = req.SNI

		caddyContent := fmt.Sprintf(`:%d {
    tls "/etc/vpn-protocols/certs/cert.pem" "/etc/vpn-protocols/certs/key.pem"
    forward_proxy {
        basic_auth "%s" "%s"
        hide_ip
        hide_via
        probe_resistance
    }
}
`, req.Port, req.Username, req.Password)
		if err := os.WriteFile("/etc/vpn-protocols/Caddyfile", []byte(caddyContent), 0644); err != nil {
			log.Println("Error writing Caddyfile:", err)
		}
		go exec.Command("systemctl", "restart", "caddy").Run()

	case "WARP":
		cfg.WarpLicenseKey = req.Password
		if req.Password != "" {
			log.Println("Upgrading WARP license key via wgcf...")
			if err := upgradeWarpLicenseKey(req.Password); err != nil {
				cfgMu.Unlock()
				log.Println("Error upgrading WARP license key:", err)
				http.Error(w, "Failed to activate WARP+ key: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

	default:
		cfgMu.Unlock()
		http.Error(w, "Unsupported protocol", http.StatusMethodNotAllowed)
		return
	}
	cfgMu.Unlock()

	saveConfig()
	adjustFirewallRules(oldPort, req.Port, req.Protocol)
	applyRoutingChanges()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Success"))
}

func handleGetProtocolSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkSession(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cfgMu.RLock()
	defer cfgMu.RUnlock()

	settings := map[string]map[string]interface{}{
		"Hysteria2": {
			"port":     cfg.HysteriaPort,
			"username": "",
			"password": cfg.HysteriaPassword,
			"sni":      cfg.HysteriaSNI,
		},
		"Mieru": {
			"port":     cfg.MieruPort,
			"username": cfg.MieruUser,
			"password": cfg.MieruPassword,
			"sni":      "",
		},
		"AnyTLS": {
			"port":     cfg.AnyTLSPort,
			"username": "",
			"password": cfg.AnyTLSPassword,
			"sni":      cfg.AnyTLSSNI,
		},
		"NaiveProxy": {
			"port":     cfg.NaivePort,
			"username": cfg.NaiveUser,
			"password": cfg.NaivePassword,
			"sni":      cfg.NaiveSNI,
		},
		"WARP": {
			"port":     0,
			"username": "",
			"password": cfg.WarpLicenseKey,
			"sni":      "",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func adjustFirewallRules(oldPort, newPort int, protocol string) {
	if oldPort == newPort {
		return
	}

	isTCP := true
	isUDP := false
	if protocol == "Hysteria2" {
		isTCP = false
		isUDP = true
	} else if protocol == "Mieru" {
		isUDP = true
	}

	if oldPort > 0 {
		log.Printf("Closing old port %d for protocol %s", oldPort, protocol)
		if isTCP {
			deleteFirewallPort(oldPort, "tcp")
		}
		if isUDP {
			deleteFirewallPort(oldPort, "udp")
		}
	}

	if newPort > 0 {
		log.Printf("Opening new port %d for protocol %s", newPort, protocol)
		if isTCP {
			allowFirewallPort(newPort, "tcp")
		}
		if isUDP {
			allowFirewallPort(newPort, "udp")
		}
	}
}

func allowFirewallPort(port int, proto string) {
	if hasCommand("ufw") {
		exec.Command("ufw", "allow", fmt.Sprintf("%d/%s", port, proto)).Run()
	} else if hasCommand("firewall-cmd") {
		exec.Command("firewall-cmd", "--zone=public", fmt.Sprintf("--add-port=%d/%s", port, proto), "--permanent").Run()
		exec.Command("firewall-cmd", "--reload").Run()
	} else {
		exec.Command("iptables", "-I", "INPUT", "-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT").Run()
	}

	exec.Command("iptables", "-I", "INPUT", "-p", proto, "--dport", fmt.Sprintf("%d", port)).Run()
	exec.Command("iptables", "-I", "OUTPUT", "-p", proto, "--sport", fmt.Sprintf("%d", port)).Run()
}

func deleteFirewallPort(port int, proto string) {
	if hasCommand("ufw") {
		exec.Command("ufw", "delete", "allow", fmt.Sprintf("%d/%s", port, proto)).Run()
	} else if hasCommand("firewall-cmd") {
		exec.Command("firewall-cmd", "--zone=public", fmt.Sprintf("--remove-port=%d/%s", port, proto), "--permanent").Run()
		exec.Command("firewall-cmd", "--reload").Run()
	} else {
		exec.Command("iptables", "-D", "INPUT", "-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT").Run()
	}

	exec.Command("iptables", "-D", "INPUT", "-p", proto, "--dport", fmt.Sprintf("%d", port)).Run()
	exec.Command("iptables", "-D", "OUTPUT", "-p", proto, "--sport", fmt.Sprintf("%d", port)).Run()
}

func hasCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func upgradeWarpLicenseKey(key string) error {
	tempDir, err := os.MkdirTemp("", "wgcf_upgrade")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	cmdReg := exec.Command("/usr/local/bin/wgcf", "register", "--accept-tos")
	cmdReg.Dir = tempDir
	if err := cmdReg.Run(); err != nil {
		return fmt.Errorf("error registering warp account: %w", err)
	}

	cmdUpdate := exec.Command("/usr/local/bin/wgcf", "update", "--license-key", key)
	cmdUpdate.Dir = tempDir
	if out, err := cmdUpdate.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply license key: %s", string(out))
	}

	cmdGen := exec.Command("/usr/local/bin/wgcf", "generate")
	cmdGen.Dir = tempDir
	if err := cmdGen.Run(); err != nil {
		return fmt.Errorf("failed to generate wireguard profile: %w", err)
	}

	profilePath := filepath.Join(tempDir, "wgcf-profile.conf")
	profileBytes, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read generated profile: %w", err)
	}
	profile := string(profileBytes)

	var privKey, addrV4, addrV6 string
	var reserved = []int{0, 0, 0}

	lines := strings.Split(profile, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "privatekey") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				privKey = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(strings.ToLower(line), "address") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				addrs := strings.Split(parts[1], ",")
				if len(addrs) >= 1 {
					addrV4 = strings.TrimSpace(addrs[0])
				}
				if len(addrs) >= 2 {
					addrV6 = strings.TrimSpace(addrs[1])
				}
			}
		} else if strings.Contains(strings.ToLower(line), "reserved") {
			startIdx := strings.Index(line, "[")
			endIdx := strings.Index(line, "]")
			if startIdx != -1 && endIdx != -1 && startIdx < endIdx {
				arrStr := line[startIdx+1 : endIdx]
				parts := strings.Split(arrStr, ",")
				if len(parts) == 3 {
					fmt.Sscanf(parts[0], "%d", &reserved[0])
					fmt.Sscanf(parts[1], "%d", &reserved[1])
					fmt.Sscanf(parts[2], "%d", &reserved[2])
				}
			}
		}
	}

	if privKey == "" || addrV4 == "" {
		return fmt.Errorf("could not parse profile options")
	}

	creds := map[string]interface{}{
		"private_key":      privKey,
		"local_address_v4": addrV4,
		"local_address_v6": addrV6,
		"reserved":         reserved,
	}
	credsBytes, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile("/etc/vpn-protocols/warp-credentials.json", credsBytes, 0644); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	return nil
}






