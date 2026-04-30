package config

import (
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Port               string
	RSAPublicKeyPath   string
	ChatServiceURL     string
	AuthServiceURL     string
	CORSAllowedOrigins string
}

func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	return &Config{
		Port:               getEnv("PORT", "8080"),
		RSAPublicKeyPath:   getEnv("RSA_PUBLIC_KEY_PATH", "../.secrets/public.pem"),
		ChatServiceURL:     getEnv("CHAT_SERVICE_URL", "http://localhost:3002"),
		AuthServiceURL:     getEnv("AUTH_SERVICE_URL", "http://localhost:3001"),
		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		trimmed := strings.TrimSpace(value)
		return strings.TrimRight(trimmed, "/")
	}
	return fallback
}
