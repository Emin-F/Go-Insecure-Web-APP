package middleware

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
)

// JWTMiddleware handles JWT authentication
type JWTMiddleware struct {
	Secret []byte
}

// NewJWTMiddleware creates a new instance of JWTMiddleware
func NewJWTMiddleware(secret []byte) *JWTMiddleware {
	return &JWTMiddleware{Secret: secret}
}

// Middleware function to validate JWT tokens
func (jm *JWTMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		type MyCookieParser struct {
			Token string `cookie:"token"`
		}
		p := new(MyCookieParser)
		if err := c.CookieParser(p); err != nil {
			return err
		}
		tokenString := p.Token
		fmt.Println("token from header:", tokenString)
		//tokenString := c.Query("token")

		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).SendString("Missing token")
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jm.Secret, nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid token")
		}

		// Pass userID to the request context
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Locals("userID", claims["userID"])
		} else {
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid token")
		}

		return c.Next()
	}
}

func (jm *JWTMiddleware) AdminMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		type MyCookieParser struct {
			Token string `cookie:"token"`
		}
		p := new(MyCookieParser)
		if err := c.CookieParser(p); err != nil {
			return err
		}
		tokenString := p.Token

		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).SendString("Missing token")
		}

		// Parse the token without verifying it
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// No need to verify token's signature
			return nil, nil
		})
		// Check claims for isAdmin
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			isAdmin, isAdminOk := claims["isAdmin"].(string)
			if isAdminOk && isAdmin == "1" {
				return c.Next()
			}
		}

		if err != nil {
			return c.Status(fiber.StatusUnauthorized).SendString("Error parsing token")
		}

		return c.Status(fiber.StatusForbidden).SendString("Forbidden: Admin access required")
	}
}
