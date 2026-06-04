package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"

	fws "github.com/fasthttp/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/proxy"
	"github.com/valyala/fasthttp"
	"mikhailjbs/api-gateway/config"
	"mikhailjbs/api-gateway/middleware"
)

func main() {
	cfg := config.Load()

	app := fiber.New()

	// ── CORS ─────────────────────────────────────────────────────────────────
	// Must be at the gateway level because proxy.Do strips the Origin header,
	// so downstream services can't set ACAO themselves for cross-origin requests.
	app.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.CORSAllowedOrigins,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	}))

	authMiddleware, err := middleware.NewAuthMiddleware(cfg.RSAPublicKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize auth middleware: %v", err)
	}

	// ── Health ────────────────────────────────────────────────────────────────
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("Gateway is healthy")
	})

	// ── Downstream Health (Public) ─────────────────────────────────────────────
	// These satisfy GitHub Actions health checks during deployment.
	app.Get("/auth/health", func(c *fiber.Ctx) error {
		targetURL := cfg.AuthServiceURL + "/health"
		log.Printf("Attempting proxy to: %s", targetURL)
		
		err := proxy.Do(c, targetURL)
		
		log.Printf("Proxy completed. Error: %v, Status Code: %d", err, c.Response().StatusCode())
		return err
	})
	app.Get("/chat/health", func(c *fiber.Ctx) error {
		err := proxy.Do(c, cfg.ChatServiceURL+"/health")
		if err != nil {
			log.Printf("proxy.Do /chat/health error: %v", err)
		}
		return err
	})
	app.Get("/thothai/health", func(c *fiber.Ctx) error {
		err := proxy.Do(c, cfg.ThothaiServiceURL+"/health")
		if err != nil {
			log.Printf("proxy.Do /thothai/health error: %v", err)
		}
		return err
	})

	// ── Auth service routes (unauthenticated passthrough) ─────────────────────
	app.All("/api/v1/auth/*", func(c *fiber.Ctx) error {
		url := cfg.AuthServiceURL + c.OriginalURL()
		return proxy.Do(c, url)
	})

	// ── HTML page routes to Auth Service ──────────────────────────────────────
	app.All("/login", func(c *fiber.Ctx) error { return proxy.Do(c, cfg.AuthServiceURL+c.OriginalURL()) })
	app.All("/register", func(c *fiber.Ctx) error { return proxy.Do(c, cfg.AuthServiceURL+c.OriginalURL()) })
	app.All("/profile", func(c *fiber.Ctx) error { return proxy.Do(c, cfg.AuthServiceURL+c.OriginalURL()) })

	// ── User routes → Auth Service (protected) ────────────────────────────────
	app.All("/api/v1/users", authMiddleware, func(c *fiber.Ctx) error {
		return proxy.Do(c, cfg.AuthServiceURL+c.OriginalURL())
	})
	app.All("/api/v1/users/*", authMiddleware, func(c *fiber.Ctx) error {
		return proxy.Do(c, cfg.AuthServiceURL+c.OriginalURL())
	})

	// ── WebSocket proxy (authenticated) ──────────────────────────────────────
	// The gateway validates the JWT and injects X-User-* headers, then
	// upgrades and tunnels the WebSocket connection to the chat service.
	app.Get("/api/v1/ws", authMiddleware, func(c *fiber.Ctx) error {
		return wsProxy(c, cfg.ChatServiceURL)
	})

	// ── Thothai routes (protected) ────────────────────────────────────────────
	// MUST be registered before the chat catch-all below — Fiber matches in
	// registration order, and chatGroup.All("/*") would otherwise swallow these.
	// The gateway validates the JWT and injects X-User-* headers; thothai trusts them.
	thothaiProxy := func(c *fiber.Ctx) error {
		return proxy.Do(c, cfg.ThothaiServiceURL+c.OriginalURL())
	}
	thothai := app.Group("/api/v1", authMiddleware)
	thothai.All("/chat/*", thothaiProxy)
	thothai.All("/search/*", thothaiProxy)
	thothai.All("/cvs/*", thothaiProxy)
	thothai.All("/cvs", thothaiProxy)
	thothai.All("/jobs/*", thothaiProxy)
	thothai.Get("/history", thothaiProxy)

	// ── Chat REST routes (protected) ──────────────────────────────────────────
	chatGroup := app.Group("/api/v1", authMiddleware)
	chatGroup.All("/*", func(c *fiber.Ctx) error {
		return proxy.Do(c, cfg.ChatServiceURL+c.OriginalURL())
	})

	log.Printf("Gateway listening on port %s", cfg.Port)
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// wsProxy upgrades the client connection and tunnels it to the upstream chat service.
func wsProxy(c *fiber.Ctx, chatServiceURL string) error {
	// Build upstream WS URL from the HTTP base URL
	upstream := strings.Replace(chatServiceURL, "http://", "ws://", 1)
	upstream = strings.Replace(upstream, "https://", "wss://", 1)
	upstream += c.OriginalURL() // includes /api/v1/ws and any query params

	// Dialer to upstream (skip TLS verify for localhost dev)
	dialer := fws.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}

	// Forward the X-User-* headers set by authMiddleware
	upstreamHeaders := http.Header{}
	for _, h := range []string{"X-User-Id", "X-User-Email", "X-User-Username", "X-User-Roles"} {
		if v := string(c.Request().Header.Peek(h)); v != "" {
			upstreamHeaders.Set(h, v)
		}
	}
	// Forward cookies too, so the chat service can read them if needed
	if cookie := string(c.Request().Header.Peek("Cookie")); cookie != "" {
		upstreamHeaders.Set("Cookie", cookie)
	}

	upstreamConn, resp, err := dialer.Dial(upstream, upstreamHeaders)
	if err != nil {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		log.Printf("ws upstream dial error: %v (status %d)", err, code)
		return fmt.Errorf("failed to connect to upstream WS: %w", err)
	}

	// Upgrade client connection.
	// IMPORTANT: the entire relay must run inside this callback — the WS connection
	// only lives for the duration of the handler func. Returning early closes it.
	upgrader := fws.FastHTTPUpgrader{
		CheckOrigin: func(_ *fasthttp.RequestCtx) bool { return true }, // CORS already handled at gateway level
	}

	return upgrader.Upgrade(c.Context(), func(clientConn *fws.Conn) {
		defer upstreamConn.Close()

		errc := make(chan error, 2)

		// client → upstream
		go func() {
			for {
				mt, msg, err := clientConn.ReadMessage()
				if err != nil {
					errc <- err
					return
				}
				if err := upstreamConn.WriteMessage(mt, msg); err != nil {
					errc <- err
					return
				}
			}
		}()

		// upstream → client
		go func() {
			for {
				mt, msg, err := upstreamConn.ReadMessage()
				if err != nil {
					errc <- err
					return
				}
				if err := clientConn.WriteMessage(mt, msg); err != nil {
					errc <- err
					return
				}
			}
		}()

		// Block until one side disconnects
		<-errc
	})
}
