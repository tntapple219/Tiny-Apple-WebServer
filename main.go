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

// --- 資料結構 ---

type Config struct {
	Domains []DomainConfig `json:"domains"`
	mu      sync.RWMutex
}

type DomainConfig struct {
	Domain                  string `json:"domain"`
	Type                    string `json:"type"` // file_server, php, reverse_proxy
	Root                    string `json:"root,omitempty"`
	ProxyURL                string `json:"proxy_url,omitempty"`
	PHPSocket               string `json:"php_socket,omitempty"`
	SSLMode                 string `json:"ssl_mode"` // "none", "lets_encrypt", "self_signed", "custom"
	SSLCertFile             string `json:"ssl_cert_file,omitempty"`
	SSLKeyFile              string `json:"ssl_key_file,omitempty"`
	ProxyInsecureSkipVerify bool   `json:"proxy_insecure_skip_verify,omitempty"` // --- 新增欄位 ---
}

var config = &Config{
	Domains: []DomainConfig{},
}

const configFile = "config.json"

// --- 證書快取 ---

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

// --- 設定檔處理 ---

func loadConfig() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("找不到 config.json，將使用空配置。")
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

// --- 自簽名證書生成 ---

func generateAndCacheSelfSignedCert(domain string) (*tls.Certificate, error) {
	if cert, found := selfSignedCertCache.Get(domain); found {
		return cert, nil
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("無法生成 RSA 金鑰: %v", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("無法生成序列號: %v", err)
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
		return nil, fmt.Errorf("無法創建證書: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("無法載入生成的金鑰對: %v", err)
	}
	selfSignedCertCache.Set(domain, &cert)
	log.Printf("為 %s 生成並快取了自簽名證書", domain)
	return &cert, nil
}

// --- HTTP 處理器 ---

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
	config.mu.Lock()
	for _, d := range config.Domains {
		if d.Domain == domain.Domain {
			http.Error(w, "域名已存在", http.StatusBadRequest)
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
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(domain)
}

func apiDomainsDelete(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/api/domains/")
	config.mu.Lock()
	newDomains := []DomainConfig{}
	found := false
	for _, d := range config.Domains {
		if d.Domain != domain {
			newDomains = append(newDomains, d)
		} else {
			found = true
		}
	}
	config.Domains = newDomains
	config.mu.Unlock()
	if !found {
		http.Error(w, "找不到域名", http.StatusNotFound)
		return
	}
	if err := saveConfig(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

// --- 已修改 ---
func proxyHandler(w http.ResponseWriter, r *http.Request, domainCfg DomainConfig) {
	targetURL := domainCfg.ProxyURL
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "無效的代理 URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// --- 核心邏輯：根據設定修改 Transport ---
	if domainCfg.ProxyInsecureSkipVerify && target.Scheme == "https" {
		log.Printf("為 %s 啟用不安全的 HTTPS 反向代理 (忽略證書驗證)", target.Host)
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		proxy.Transport = transport
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("代理錯誤: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

// --- 已修改 ---
func mainHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	config.mu.RLock()
	defer config.mu.RUnlock()
	for _, d := range config.Domains {
		if d.Domain == host {
			switch d.Type {
			case "file_server":
				fileServerHandler(w, r, d.Root)
			case "php":
				phpHandler(w, r, d.Root, d.PHPSocket)
			case "reverse_proxy":
				proxyHandler(w, r, d) // 現在傳遞整個 d 物件
			default:
				http.Error(w, "未知的服務類型", http.StatusInternalServerError)
			}
			return
		}
	}
	http.NotFound(w, r)
}

// --- 主函式 ---

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("❌ 載入配置失敗: %v", err)
	}
	// --- 1. 啟動獨立的管理伺服器 ---
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
		log.Printf("🚀 管理面板啟動成功! 請訪問: http://localhost%s/admin", adminPort)
		if err := http.ListenAndServe(adminPort, adminMux); err != nil {
			log.Fatalf("❌ 管理伺服器啟動失敗: %v", err)
		}
	}()

	// --- 2. 設定主 Web 服務 ---
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
							log.Printf("為 %s 載入自訂證書失敗: %v", d.Domain, err)
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
			return nil, fmt.Errorf("未找到域名 %s 的證書配置", hello.ServerName)
		},
	}
	// 3a. 啟動 HTTP 伺服器 (80端口)，用於重定向和 ACME 驗證
	go func() {
		handler := certManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetURL := "https://" + r.Host + r.URL.Path
			http.Redirect(w, r, targetURL, http.StatusPermanentRedirect)
		}))
		log.Println("🌍 主 Web 服務 (HTTP) 正在監聽 :80")
		if err := http.ListenAndServe(":80", handler); err != nil {
			log.Printf("⚠️  HTTP 伺服器 (:80) 啟動失敗: %v (可能是權限不足)", err)
		}
	}()
	// 3b. 啟動 HTTPS 伺服器 (443端口)
	httpsServer := &http.Server{
		Addr:      ":443",
		Handler:   http.HandlerFunc(mainHandler),
		TLSConfig: tlsConfig,
	}
	log.Println("🌍 主 Web 服務 (HTTPS) 正在監聽 :443")
	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		log.Printf("⚠️  HTTPS 伺服器 (:443) 啟動失敗: %v (可能是權限不足)", err)
	}
	select {}
}
