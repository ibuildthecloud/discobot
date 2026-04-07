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
	svc := service.New(st, cfg)
	h := handler.New(cfg, svc)
	addr := ":" + httpPort(cfg.Port)
	log.Printf("discobot auth service listening on %s", addr)
	log.Printf("public issuer: %s", cfg.PublicBaseURL())
	if err := http.ListenAndServe(addr, h.Router()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func httpPort(port int) string {
	return fmt.Sprintf("%d", port)
}
