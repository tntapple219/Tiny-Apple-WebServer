package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yookoala/gofast"
	"golang.org/x/crypto/acme/autocert"
)

// --- Data Structures ---

type Config struct {
	Domains []DomainConfig `json:"domains"`
	mu      sync.RWMutex
}

type DomainConfig struct {
	Domain                  string `json:"domain"` // Supports "example.com" or ":8080"
	Type                    string `json:"type"`   // file_server, php, reverse_proxy
	Root                    string `json:"root,omitempty"`
	ProxyURL                string `json:"proxy_url,omitempty"`
	PHPSocket               string `json:"php_socket,omitempty"`
	SSLMode                 string `json:"ssl_mode"` // "none", "lets_encrypt", "self_signed", "custom"
	SSLCertFile             string `json:"ssl_cert_file,omitempty"`
	SSLKeyFile              string `json:"ssl_key_file,omitempty"`
	ProxyInsecureSkipVerify bool   `json:"proxy_insecure_skip_verify,omitempty"`
}

var config = &Config{
	Domains: []DomainConfig{},
}

const configFile = "config.json"

// --- Port Management ---

type PortManager struct {
	mu       sync.RWMutex
	servers  map[string]*http.Server // port -> server instance
	contexts map[string]context.CancelFunc // port -> cancel function
}

var portManager = &PortManager{
	servers:  make(map[string]*http.Server),
	contexts: make(map[string]context.CancelFunc),
}

// StartPort dynamically starts a server on the specified port
func (pm *PortManager) StartPort(port string, handler http.Handler, tlsConfig *tls.Config) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if port is already running
	if _, exists := pm.servers[port]; exists {
		log.Printf("ℹ️  Port %s is already running", port)
		return nil
	}

	addr := ":" + port
	ctx, cancel := context.WithCancel(context.Background())
	
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	pm.servers[port] = server
	pm.contexts[port] = cancel

	// Start server in goroutine
	go func() {
		var err error
		if port == "443" && tlsConfig != nil {
			server.TLSConfig = tlsConfig
			log.Printf("🔒 Starting HTTPS server on: %s", addr)
			err = server.ListenAndServeTLS("", "")
		} else {
			log.Printf("🌐 Starting HTTP server on: %s", addr)
			err = server.ListenAndServe()
		}
		
		if err != nil && err != http.ErrServerClosed {
			log.Printf("⚠️  Server on %s stopped with error: %v", addr, err)
		}
	}()

	log.Printf("✅ Successfully started server on port %s", port)
	return nil
}

// StopPort gracefully stops the server on the specified port
func (pm *PortManager) StopPort(port string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	cancel, hasCancel := pm.contexts[port]
	server, hasServer := pm.servers[port]

	if !hasCancel || !hasServer {
		return fmt.Errorf("port %s is not running", port)
	}

	// Signal shutdown
	cancel()

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("⚠️  Error during shutdown of port %s: %v", port, err)
		return err
	}

	// Cleanup
	delete(pm.servers, port)
	delete(pm.contexts, port)

	log.Printf("🛑 Successfully stopped server on port %s", port)
	return nil
}

// IsPortRunning checks if a port is currently being served
func (pm *PortManager) IsPortRunning(port string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, exists := pm.servers[port]
	return exists
}

// GetActivePorts returns a list of all currently active ports
func (pm *PortManager) GetActivePorts() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	ports := make([]string, 0, len(pm.servers))
	for port := range pm.servers {
		ports = append(ports, port)
	}
	return ports
}

// --- Certificate Cache ---

type CertCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

func (c *CertCache) Get(name string) (*tls.Certificate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cert, found := c.certs[name]
	return cert, found
}

func (c *CertCache) Set(name string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs[name] = cert
}

var customCertCache = &CertCache{certs: make(map[string]*tls.Certificate)}
var selfSignedCertCache = &CertCache{certs: make(map[string]*tls.Certificate)}

// --- Configuration File Handling ---

func loadConfig() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("config.json not found, using empty configuration.")
			return nil
		}
		return err
	}
	return json.Unmarshal(data, config)
}

func saveConfig() error {
	config.mu.Lock()
	defer config.mu.Unlock()
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
}

// --- Self-Signed Certificate Generation ---

func generateAndCacheSelfSignedCert(domain string) (*tls.Certificate, error) {
	if cert, found := selfSignedCertCache.Get(domain); found {
		return cert, nil
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Self-Signed Corp"}, CommonName: domain},
		NotBefore:    notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{domain},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load generated key pair: %v", err)
	}
	selfSignedCertCache.Set(domain, &cert)
	log.Printf("Generated and cached self-signed certificate for %s", domain)
	return &cert, nil
}

// --- HTTP Handlers ---

func guiHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

func apiDomainsGet(w http.ResponseWriter, r *http.Request) {
	config.mu.RLock()
	defer config.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config.Domains)
}

func apiDomainsPost(w http.ResponseWriter, r *http.Request) {
	var domain DomainConfig
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate against self-referencing proxy loop
	if domain.Type == "reverse_proxy" && strings.HasPrefix(domain.Domain, ":") {
		listenPort := strings.TrimPrefix(domain.Domain, ":")
		if proxyURL, err := url.Parse(domain.ProxyURL); err == nil {
			proxyHost := proxyURL.Host
			// Check if proxy target points to itself
			if proxyHost == "localhost:"+listenPort ||
				proxyHost == "127.0.0.1:"+listenPort ||
				proxyHost == ":"+listenPort {
				http.Error(w, "Error: Proxy target cannot point to its own port (infinite loop)", http.StatusBadRequest)
				return
			}
		}
	}

	// Auto-correct SSL mode for :port format (port-based configs don't support SSL)
	if strings.HasPrefix(domain.Domain, ":") && domain.SSLMode != "" && domain.SSLMode != "none" {
		log.Printf("⚠️  Warning: Port-based domain '%s' doesn't support SSL. Auto-correcting ssl_mode to 'none'", domain.Domain)
		domain.SSLMode = "none"
	}

	config.mu.Lock()
	for _, d := range config.Domains {
		if d.Domain == domain.Domain {
			http.Error(w, "Domain already exists", http.StatusBadRequest)
			config.mu.Unlock()
			return
		}
	}
	config.Domains = append(config.Domains, domain)
	config.mu.Unlock()
	
	if err := saveConfig(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 🎯 Start listening on new port immediately if it's a :port config
	if strings.HasPrefix(domain.Domain, ":") {
		port := strings.TrimPrefix(domain.Domain, ":")
		if !portManager.IsPortRunning(port) {
			go func() {
				if err := portManager.StartPort(port, http.HandlerFunc(mainHandler), nil); err != nil {
					log.Printf("❌ Failed to start port %s: %v", port, err)
				}
			}()
		}
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(domain)
}

func apiDomainsDelete(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/api/domains/")
	
	var deletedDomain DomainConfig
	config.mu.Lock()
	newDomains := []DomainConfig{}
	found := false
	for _, d := range config.Domains {
		if d.Domain != domain {
			newDomains = append(newDomains, d)
		} else {
			found = true
			deletedDomain = d
		}
	}
	config.Domains = newDomains
	config.mu.Unlock()
	
	if !found {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}
	
	if err := saveConfig(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 🗑️ Stop port if it was a :port config and no other configs use it
	if strings.HasPrefix(deletedDomain.Domain, ":") {
		port := strings.TrimPrefix(deletedDomain.Domain, ":")
		
		// Check if any other configs still use this port
		config.mu.RLock()
		portStillInUse := false
		for _, d := range config.Domains {
			if d.Domain == deletedDomain.Domain {
				portStillInUse = true
				break
			}
		}
		config.mu.RUnlock()

		// Only stop if port is not used by other configs and not default port
		if !portStillInUse && port != "80" && port != "443" {
			if portManager.IsPortRunning(port) {
				go func() {
					if err := portManager.StopPort(port); err != nil {
						log.Printf("⚠️  Failed to stop port %s: %v", port, err)
					}
				}()
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func fileServerHandler(w http.ResponseWriter, r *http.Request, root string) {
	if root == "" {
		root = "."
	}
	http.FileServer(http.Dir(root)).ServeHTTP(w, r)
}

func phpHandler(w http.ResponseWriter, r *http.Request, root, socket string) {
	if root == "" {
		root = "."
	}
	scriptPath := filepath.Join(root, r.URL.Path)
	if info, err := os.Stat(scriptPath); err == nil && info.IsDir() {
		scriptPath = filepath.Join(scriptPath, "index.php")
	}
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		if !strings.HasSuffix(r.URL.Path, ".php") {
			http.ServeFile(w, r, filepath.Join(root, r.URL.Path))
			return
		}
		http.NotFound(w, r)
		return
	}
	var connFactory gofast.ConnFactory
	if strings.Contains(socket, ":") {
		connFactory = gofast.SimpleConnFactory("tcp", socket)
	} else {
		connFactory = gofast.SimpleConnFactory("unix", socket)
	}
	h := gofast.NewHandler(
		gofast.NewPHPFS(root)(gofast.BasicSession),
		gofast.SimpleClientFactory(connFactory),
	)
	h.ServeHTTP(w, r)
}

func proxyHandler(w http.ResponseWriter, r *http.Request, domainCfg DomainConfig) {
	targetURL := domainCfg.ProxyURL
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid proxy URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Configure transport based on settings
	if domainCfg.ProxyInsecureSkipVerify && target.Scheme == "https" {
		log.Printf("Enabling insecure HTTPS reverse proxy for %s (skipping certificate verification)", target.Host)
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		proxy.Transport = transport
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

// --- Main Request Handler with :port support ---

func mainHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	var hostname, port string

	// Separate hostname and port
	if h, p, err := net.SplitHostPort(r.Host); err == nil {
		hostname = h
		port = p
	} else {
		hostname = host
		// Determine default port based on scheme
		if r.TLS != nil {
			port = "443"
		} else {
			port = "80"
		}
	}

	config.mu.RLock()
	defer config.mu.RUnlock()

	for _, d := range config.Domains {
		matched := false

		// Case 1: Config is in :port format (e.g., ":8080")
		if strings.HasPrefix(d.Domain, ":") {
			configPort := strings.TrimPrefix(d.Domain, ":")
			if configPort == port {
				matched = true
				log.Printf("✅ Port matched: %s -> %s (type: %s)", r.Host, d.Domain, d.Type)
			}
		} else {
			// Case 2: Normal domain matching
			if d.Domain == hostname {
				matched = true
				log.Printf("✅ Domain matched: %s -> %s (type: %s)", hostname, d.Domain, d.Type)
			}
		}

		if matched {
			switch d.Type {
			case "file_server":
				fileServerHandler(w, r, d.Root)
			case "php":
				phpHandler(w, r, d.Root, d.PHPSocket)
			case "reverse_proxy":
				proxyHandler(w, r, d)
			default:
				http.Error(w, "Unknown service type", http.StatusInternalServerError)
			}
			return
		}
	}

	log.Printf("❌ No matching configuration found: host=%s, port=%s", hostname, port)
	http.NotFound(w, r)
}

// --- Main Function ---

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("❌ Failed to load configuration: %v", err)
	}

	// 1. Start independent admin server
	go func() {
		adminMux := http.NewServeMux()
		adminMux.HandleFunc("/admin", guiHandler)
		staticFileServer := http.FileServer(http.Dir("static"))
		adminMux.Handle("/static/", http.StripPrefix("/static/", staticFileServer))
		adminMux.HandleFunc("/api/domains", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				apiDomainsGet(w, r)
			} else if r.Method == "POST" {
				apiDomainsPost(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})
		adminMux.HandleFunc("/api/domains/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "DELETE" {
				apiDomainsDelete(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})
		adminPort := ":9999"
		log.Printf("🚀 Admin panel started! Visit: http://localhost%s/admin", adminPort)
		if err := http.ListenAndServe(adminPort, adminMux); err != nil {
			log.Fatalf("❌ Admin server failed to start: %v", err)
		}
	}()

	// 2. Configure TLS certificate manager
	certManager := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			config.mu.RLock()
			defer config.mu.RUnlock()
			for _, d := range config.Domains {
				if d.Domain == host && d.SSLMode == "lets_encrypt" {
					return nil
				}
			}
			return fmt.Errorf("acme/autocert: host %q not configured for lets_encrypt", host)
		},
		Cache: autocert.DirCache("certs"),
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			config.mu.RLock()
			defer config.mu.RUnlock()
			for _, d := range config.Domains {
				if d.Domain == hello.ServerName {
					switch d.SSLMode {
					case "lets_encrypt":
						return certManager.GetCertificate(hello)
					case "custom":
						if cert, found := customCertCache.Get(d.Domain); found {
							return cert, nil
						}
						cert, err := tls.LoadX509KeyPair(d.SSLCertFile, d.SSLKeyFile)
						if err != nil {
							log.Printf("Failed to load custom certificate for %s: %v", d.Domain, err)
							return nil, err
						}
						customCertCache.Set(d.Domain, &cert)
						return &cert, nil
					case "self_signed":
						return generateAndCacheSelfSignedCert(d.Domain)
					}
					break
				}
			}
			return nil, fmt.Errorf("no certificate configuration found for domain %s", hello.ServerName)
		},
	}

	// 3. Start default ports (80, 443)
	mainHTTPHandler := certManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if there's a :80 configuration
		config.mu.RLock()
		hasPort80Config := false
		for _, d := range config.Domains {
			if d.Domain == ":80" {
				hasPort80Config = true
				break
			}
		}
		config.mu.RUnlock()

		if hasPort80Config {
			// Has :80 config, use normal handler
			mainHandler(w, r)
		} else {
			// No :80 config, redirect to HTTPS
			targetURL := "https://" + r.Host + r.URL.Path
			if r.URL.RawQuery != "" {
				targetURL += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, targetURL, http.StatusPermanentRedirect)
		}
	}))

	// Start port 80
	go portManager.StartPort("80", mainHTTPHandler, nil)
	
	// Start port 443
	go portManager.StartPort("443", http.HandlerFunc(mainHandler), tlsConfig)

	// 4. Start custom ports from existing config
	config.mu.RLock()
	for _, d := range config.Domains {
		if strings.HasPrefix(d.Domain, ":") {
			port := strings.TrimPrefix(d.Domain, ":")
			if port != "80" && port != "443" && !portManager.IsPortRunning(port) {
				go portManager.StartPort(port, http.HandlerFunc(mainHandler), nil)
			}
		}
	}
	config.mu.RUnlock()

	log.Println("✅ All servers started successfully")
	log.Printf("📊 Active ports: %v", portManager.GetActivePorts())
	
	select {} // Keep program running
}