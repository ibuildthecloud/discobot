package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/joho/godotenv"

	"github.com/obot-platform/discobot/authservice/internal/config"
	"github.com/obot-platform/discobot/authservice/internal/database"
	"github.com/obot-platform/discobot/authservice/internal/handler"
	"github.com/obot-platform/discobot/authservice/internal/service"
	"github.com/obot-platform/discobot/authservice/internal/store"
	"github.com/obot-platform/discobot/authservice/internal/tlsconfig"
)

func main() {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	db, err := database.New(cfg)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("failed to close database: %v", err)
		}
	}()
	if err := db.Migrate(); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}
	st := store.New(db.DB, db.ReadDB)
	httpsSetup, err := tlsconfig.Load(cfg, st)
	if err != nil {
		log.Fatalf("failed to initialize HTTPS configuration: %v", err)
	}
	svc := service.New(st, cfg)
	h := handler.New(cfg, svc)
	router := h.Router()
	addr := ":" + httpPort(cfg.Port)
	log.Printf("discobot auth service listening on %s", addr)
	log.Printf("public issuer: %s", cfg.PublicBaseURL())

	if httpsSetup == nil {
		if err := http.ListenAndServe(addr, router); err != nil {
			log.Fatalf("server error: %v", err)
		}
		return
	}

	httpHandler := http.Handler(router)
	if httpsSetup.RedirectHTTP {
		httpHandler = tlsconfig.RedirectHTTPToHTTPS(cfg, httpHandler)
	}
	if httpsSetup.WrapHTTPHandler != nil {
		httpHandler = httpsSetup.WrapHTTPHandler(httpHandler)
	}

	httpSrv := &http.Server{
		Addr:    addr,
		Handler: httpHandler,
	}
	httpsAddr := ":" + httpPort(cfg.HTTPSPort)
	httpsSrv := &http.Server{
		Addr:      httpsAddr,
		Handler:   router,
		TLSConfig: httpsSetup.TLSConfig,
	}

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	log.Printf("HTTPS server starting on %s (%s TLS)", httpsAddr, httpsSetup.Mode)
	if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTPS server error: %v", err)
	}
}

func httpPort(port int) string {
	return fmt.Sprintf("%d", port)
}
