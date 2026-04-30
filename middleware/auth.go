package middleware

import (
	"fmt"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func NewAuthMiddleware(pubKeyPath string) (fiber.Handler, error) {
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read public key: %w", err)
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %w", err)
	}

	return func(c *fiber.Ctx) error {
		// Allow preflight requests to bypass auth
		if c.Method() == fiber.MethodOptions {
			return c.Next()
		}

		tokenString := c.Cookies("access_token")
		if tokenString == "" {
			authHeader := c.Get("Authorization")
			if len(authHeader) > 7 && strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = authHeader[7:]
			}
		}

		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: missing token"})
		}

		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return pubKey, nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: invalid token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: invalid claims"})
		}

		if sub, ok := claims["sub"].(string); ok {
			c.Request().Header.Set("X-User-Id", sub)
		}
		if email, ok := claims["email"].(string); ok {
			c.Request().Header.Set("X-User-Email", email)
		}
		if username, ok := claims["username"].(string); ok {
			c.Request().Header.Set("X-User-Username", username)
		}
		
		if roles, ok := claims["roles"]; ok {
			switch r := roles.(type) {
			case []interface{}:
				roleStrs := make([]string, 0, len(r))
				for _, ri := range r {
					if s, ok := ri.(string); ok {
						roleStrs = append(roleStrs, s)
					}
				}
				c.Request().Header.Set("X-User-Roles", strings.Join(roleStrs, ","))
			case string:
				c.Request().Header.Set("X-User-Roles", r)
			}
		}

		return c.Next()
	}, nil
}
