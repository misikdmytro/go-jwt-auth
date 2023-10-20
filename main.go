package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"

	_ "github.com/lib/pq"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	engine := html.New("./views", ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	privateKey, err := readPrivateKeyFromFile("keys/id_rsa")
	if err != nil {
		panic(err)
	}

	app.Use(jwtMiddleware(privateKey))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{
			"Title":           "JWT Auth",
			"Year":            time.Now().Year(),
			"Username":        c.Locals("username"),
			"IsAuthenticated": c.Locals("username") != nil,
		}, "layouts/main")
	})

	app.Get("/login", func(c *fiber.Ctx) error {
		return c.Render("login", fiber.Map{
			"Title":           "Login",
			"Year":            time.Now().Year(),
			"IsAuthenticated": c.Locals("username") != nil,
		}, "layouts/main")
	})

	app.Get("/register", func(c *fiber.Ctx) error {
		return c.Render("register", fiber.Map{
			"Title":           "Register",
			"Year":            time.Now().Year(),
			"IsAuthenticated": c.Locals("username") != nil,
		}, "layouts/main")
	})

	app.Get("/logout", logout)

	app.Post("/login", login(privateKey))
	app.Post("/register", register)

	if err := app.Listen(":3001"); err != nil {
		panic(err)
	}
}

func jwtMiddleware(privateKey *rsa.PrivateKey) fiber.Handler {
	return func(c *fiber.Ctx) error {
		jwtCookie := c.Cookies("jwt")
		if jwtCookie != "" {
			token, err := jwt.Parse(jwtCookie, func(token *jwt.Token) (interface{}, error) {
				return privateKey.Public(), nil
			})

			if err == nil {
				sub, err := token.Claims.GetSubject()
				if err != nil {
					return c.Next()
				}

				c.Locals("username", sub)
			}
		}

		return c.Next()
	}
}

func login(privateKey *rsa.PrivateKey) fiber.Handler {
	return func(c *fiber.Ctx) error {
		username := c.FormValue("username")
		password := c.FormValue("password")
		if username == "" || password == "" {
			log.Println("Missing username or password")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "Missing username or password",
			})
		}

		hash := hash(password)

		db, err := connectoToDB()
		if err != nil {
			log.Printf("Database error. Error: %v\n", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Database error",
			})
		}
		defer db.Close()

		var user User
		err = db.QueryRow("SELECT username, password FROM users WHERE username=$1", username).Scan(&user.Username, &user.Password)
		if err != nil {
			log.Printf("Database error. Error: %v\n", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Database error",
			})
		}

		if user.Password != hash {
			log.Println("Invalid username or password")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Invalid username or password",
			})
		}

		expires := time.Now().Add(time.Hour)
		claims := jwt.MapClaims{
			"iss": "admin",
			"sub": user.Username,
			"aud": "users",
			"exp": expires.Unix(),
			"nbf": time.Now().Unix(),
			"iat": time.Now().Unix(),
			"jti": uuid.NewString(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		t, err := token.SignedString(privateKey)
		if err != nil {
			log.Printf("Error signing token. Error: %v\n", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Error signing token",
			})
		}

		c.Cookie(&fiber.Cookie{
			Name:    "jwt",
			Value:   t,
			Expires: expires,
		})

		return c.Redirect("/")
	}
}

func logout(c *fiber.Ctx) error {
	c.Cookie(&fiber.Cookie{
		Name:    "jwt",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
	})

	return c.Redirect("/")
}

func register(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	if username == "" || password == "" {
		log.Println("Missing username or password")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Missing username or password",
		})
	}

	hash := hash(password)

	db, err := connectoToDB()
	if err != nil {
		log.Printf("Database error. Error: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Database error",
		})
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, hash)
	if err != nil {
		log.Printf("Database error. Error: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Database error",
		})
	}

	return c.Redirect("/")
}

func connectoToDB() (*sql.DB, error) {
	connection := os.Getenv("DATABASE_URL")
	if connection == "" {
		connection = "host=localhost port=5432 user=postgres password=postgres dbname=postgres sslmode=disable"
	}

	return sql.Open("postgres", connection)
}

func hash(str string) string {
	hash := sha3.Sum256([]byte(str))
	doubleHash := sha3.Sum256(hash[:])
	return hex.EncodeToString(doubleHash[:])
}

func readPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, _ := file.Stat()
	fileSize := fileInfo.Size()
	buffer := make([]byte, fileSize)

	_, err = file.Read(buffer)
	if err != nil {
		return nil, err
	}

	data, _ := pem.Decode(buffer)
	privateKey, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
