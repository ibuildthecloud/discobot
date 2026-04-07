package tlsconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/obot-platform/discobot/authservice/internal/config"
	"github.com/obot-platform/discobot/authservice/internal/encryption"
	"github.com/obot-platform/discobot/authservice/internal/store"
)

type Setup struct {
	Mode            string
	RedirectHTTP    bool
	TLSConfig       *tls.Config
	WrapHTTPHandler func(http.Handler) http.Handler
}

func Load(cfg *config.Config, s *store.Store) (*Setup, error) {
	if cfg.HTTPSPort <= 0 {
		return nil, nil
	}

	switch cfg.HTTPSTLSMode {
	case "ephemeral":
		cert, err := generateEphemeralCertificate(cfg.HTTPSTLSHosts)
		if err != nil {
			return nil, err
		}
		return &Setup{
			Mode:         "ephemeral",
			RedirectHTTP: false,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
			},
			WrapHTTPHandler: identityHandler,
		}, nil
	case "static":
		cert, err := tls.LoadX509KeyPair(cfg.HTTPSTLSCertFile, cfg.HTTPSTLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load static TLS certificate: %w", err)
		}
		return &Setup{
			Mode:         "static",
			RedirectHTTP: true,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
			},
			WrapHTTPHandler: identityHandler,
		}, nil
	case "acme":
		if s == nil {
			return nil, fmt.Errorf("store is required when HTTPS_TLS_MODE=acme")
		}
		encryptor, err := encryption.NewEncryptor(cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("create TLS encryptor: %w", err)
		}
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      &dbCache{store: s, encryptor: encryptor},
			HostPolicy: autocert.HostWhitelist(cfg.HTTPSTLSHosts...),
			Email:      cfg.HTTPSACMEEmail,
		}
		tlsCfg := manager.TLSConfig()
		tlsCfg.MinVersion = tls.VersionTLS12
		return &Setup{
			Mode:            "acme",
			RedirectHTTP:    true,
			TLSConfig:       tlsCfg,
			WrapHTTPHandler: manager.HTTPHandler,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported HTTPS TLS mode %q", cfg.HTTPSTLSMode)
	}
}

func identityHandler(next http.Handler) http.Handler {
	return next
}

func RedirectHTTPToHTTPS(cfg *config.Config, next http.Handler) http.Handler {
	_ = next
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetURL := *r.URL
		targetURL.Scheme = "https"
		targetURL.Host = buildHTTPSHost(r.Host, cfg.HTTPSPort)
		http.Redirect(w, r, targetURL.String(), http.StatusPermanentRedirect)
	})
}

func buildHTTPSHost(host string, httpsPort int) string {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		trimmed := strings.TrimSpace(host)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			hostname = strings.Trim(trimmed, "[]")
		} else {
			hostname = trimmed
		}
	}
	if hostname == "" {
		hostname = host
	}
	if httpsPort == 443 {
		if strings.Contains(hostname, ":") {
			return "[" + hostname + "]"
		}
		return hostname
	}
	return net.JoinHostPort(hostname, strconv.Itoa(httpsPort))
}

type dbCache struct {
	store     *store.Store
	encryptor *encryption.Encryptor
}

func (c *dbCache) Get(ctx context.Context, key string) ([]byte, error) {
	entry, err := c.store.GetTLSCacheEntry(ctx, key)
	if err != nil {
		if err == store.ErrNotFound {
			return nil, autocert.ErrCacheMiss
		}
		return nil, err
	}
	data, err := c.encryptor.Decrypt(entry.EncryptedData)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *dbCache) Put(ctx context.Context, key string, data []byte) error {
	encrypted, err := c.encryptor.Encrypt(data)
	if err != nil {
		return err
	}
	return c.store.PutTLSCacheEntry(ctx, key, encrypted)
}

func (c *dbCache) Delete(ctx context.Context, key string) error {
	return c.store.DeleteTLSCacheEntry(ctx, key)
}

func generateEphemeralCertificate(hosts []string) (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate TLS private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate TLS serial number: %w", err)
	}

	dnsNames, ipAddresses := splitHosts(hosts)
	if len(dnsNames) == 0 && len(ipAddresses) == 0 {
		dnsNames = []string{"localhost"}
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: firstHost(dnsNames, ipAddresses),
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create ephemeral TLS certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal TLS private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load generated TLS key pair: %w", err)
	}

	return cert, nil
}

func splitHosts(hosts []string) ([]string, []net.IP) {
	dnsNames := make([]string, 0, len(hosts))
	ipAddresses := make([]net.IP, 0, len(hosts))
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			ipAddresses = append(ipAddresses, ip)
			continue
		}
		dnsNames = append(dnsNames, host)
	}
	return dnsNames, ipAddresses
}

func firstHost(dnsNames []string, ipAddresses []net.IP) string {
	if len(dnsNames) > 0 {
		return dnsNames[0]
	}
	if len(ipAddresses) > 0 {
		return ipAddresses[0].String()
	}
	return "localhost"
}
