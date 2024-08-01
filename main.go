package main

//idor doğru çalışmıyor profile'dan buton'a tıkladığımda backend'e istek atması lazım o eksik
//ssti kısmında ise biraz daha güncelleme mük olur

import (
	"bytes"
	"database/sql"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	_ "github.com/mattn/go-sqlite3"
	"go-insecure-web-app/middleware"
	"html/template"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Initialize JWT middleware
var jwtSecret = []byte("your_secret_key")
var jwtMiddleware = middleware.NewJWTMiddleware(jwtSecret)

// var adminTokenCheckMiddleware = middleware.AdminTokenCheckMiddleware(jwtSecret)

type Person string

func (p Person) Secret(test string) string {
	out, _ := exec.Command(test).CombinedOutput()
	return string(out)
}

func (p Person) Label(test string) string {
	return "This is " + string(test)
}

type Inventory struct {
	Type  string
	Count int
}

func (i Inventory) EvilFunction(cmd string) string {
	exec.Command(cmd)
	return "Secret: 1241287412846818418724"
}
func sstiHandler(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodPost {
		// Handle user input
		input := c.FormValue("input")

		//inv := Inventory{"computer", 100}
		// Create a new template with user input
		tmpl, err := template.New("ssti").Parse(input)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Error parsing template")
		}

		// Execute the template and send output to user
		buf := new(bytes.Buffer)
		err = tmpl.Execute(buf, Person("burak"))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Error executing template")
		}

		return c.SendString(buf.String())
	}

	// Render HTML form
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>SSTI Test</title>
	</head>
	<body>
		<h1>SSTI Test Page</h1>
		<form method="post">
			<label for="input">Enter Template:</label>
			<input type="text" id="input" name="input" placeholder="{{ .Secret "id" }}" />
			<input type="submit" value="Submit">
		</form>
	</body>
	</html>
	`
	return c.Type("html").SendString(html)
}

func searchHandler(c *fiber.Ctx) error {
	// Retrieve the search query from the URL parameters
	query := c.Query("query")

	// HTML içerisindeki action kısmı bizim buradaki aksiyon'un istek atacağı endpoint
	//burada html'ii direkt yazdık ve stirng format koyduk buraya da aldığımızı input'u koyarak bunu yeniden send string ile run ediyoruz.
	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Search</title>
	</head>
	<body>
		<h1>Search</h1>
		<form method="get" action="/search">
			<label for="query">Search:</label>
			<input type="text" id="query" name="query" value="%s">
			<input type="submit" value="Search">
		</form>
		<h2>Search Results for: %s</h2>
	</body>
	</html>
	`, query, query)

	// Serve the HTML content
	return c.Type("html").SendString(html)
}

func main() {

	engine := html.New("./", ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("search", fiber.Map{
			"Title": "Welcome to Search Page"})
	})

	//XSS trigger
	app.Get("/search", searchHandler)
	app.Get("/ssti", sstiHandler)
	app.Post("/ssti", sstiHandler)
	app.Get("/login", func(c *fiber.Ctx) error {
		return c.SendFile("login.html")
		//burada login page açılıyor öncelikle.
	})

	app.Post("/loginapi", func(c *fiber.Ctx) error {
		// Parse form data

		username := c.FormValue("username")
		password := c.FormValue("password")

		//html ve go aynı anda kullanım açıklaması. yazdığımız html içerisindeki form isteğine endpoint ve istek tipi yazarak buradaki enpdoint'e gelmesini sağlıyoruz.
		//Yani ekstra istek oluşturmaya gerek yok direkt bu endpointi verip sonra c.FormValue ile istenilen değerleri alabiliriz.
		if username == "" || password == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Username and password are required")
		}

		// Simple response for demonstration
		// Query the database for the user
		var dbPassword string
		var userID string
		err := db.QueryRow("SELECT id, password FROM user WHERE username = ?", username).Scan(&userID, &dbPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password")
			}
			return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
		}

		// Simple password check (in a real application, you should hash and salt passwords)
		if password != dbPassword {
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password")
		}
		// Generate JWT token
		// var userID = db.QueryRow("SELECT id FROM user WHERE username = ?", username)

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"userID":   userID,
			"username": username,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})

		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to generate token")
		}

		// Redirect to profile page with token in query params
		//	return c.Redirect(fmt.Sprintf("/profile?token=%s", tokenString))
		// Login successful
		//	return c.SendString("Login successful")
		println(username)
		println(tokenString)

		resp := fiber.Map{
			"token":   tokenString,
			"user_id": userID,
		}
		//ilk olarak profile'a atsın oradan userİd olana yönlendirsin.
		//return c.Redirect(fmt.Sprintf("/profile?userid=%s", userID))
		return c.JSON(resp)
	})

	app.Get("/register", func(c *fiber.Ctx) error {
		return c.SendFile("register.html")
	})

	// Handle registration
	app.Post("/register", func(c *fiber.Ctx) error {
		// Parse form data
		username := c.FormValue("username")
		password := c.FormValue("password")

		if username == "" || password == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Username and password are required")
		}

		// Insert new user into the database
		_, err := db.Exec("INSERT INTO user (username, password) VALUES (?, ?)", username, password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to register user")
		}

		return c.SendString("User registered successfully")
	})

	app.Get("/file", func(c *fiber.Ctx) error {
		// Get the filename from the query parameter

		filename := c.Query("filename")

		// Vulnerable code: directly use filename without validation
		path := filepath.Join("files", filename)

		// Read the file content
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return c.Status(404).SendString("File not found oe you should use filename parameters")
		}

		return c.SendString(string(data))
	})

	app.Get("/rce", func(c *fiber.Ctx) error {
		return c.Render("ssti", fiber.Map{
			"Title": "Welcome to Search Page"})
	})

	app.Get("/execute", func(c *fiber.Ctx) error {
		// Get user input from query parameter
		userInput := c.Query("command")

		// Define a template that directly uses user input
		tmpl := `{{ define "T" }}{{ . }}{{ end }}{{ template "T" . }}`

		// Parse the template
		t := template.Must(template.New("vulnerable").Parse(tmpl))

		// Render the template with user input
		var builder strings.Builder
		err := t.ExecuteTemplate(&builder, "T", userInput)
		if err != nil {
			return c.Status(500).SendString("Internal Server Error")
		}

		// Execute the rendered template content as a shell command
		cmd := exec.Command("sh", "-c", builder.String())
		output, err := cmd.CombinedOutput()
		if err != nil {
			return c.Status(500).SendString("Server side execution failed")
		}

		return c.SendString(string(output))
	})

	app.Post("/profile/upload", func(c *fiber.Ctx) error {
		userID := c.Locals("userID").(int)

		// Parse the multipart form
		form, err := c.MultipartForm()
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString("Failed to parse form")
		}

		// Get the file
		files := form.File["photo"]
		if len(files) == 0 {
			return c.Status(fiber.StatusBadRequest).SendString("No file uploaded")
		}

		file := files[0]

		// Save the file
		filePath := fmt.Sprintf("uploads/%d_%s", userID, file.Filename)
		err = c.SaveFile(file, filePath)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to save file")
		}

		return c.SendString("File uploaded successfully")
	})

	// Create uploads directory if not exists
	if err := os.MkdirAll("uploads", os.ModePerm); err != nil {
		log.Fatal("Failed to create uploads directory")
	}

	app.Get("/admin", jwtMiddleware.AdminMiddleware(), func(c *fiber.Ctx) error {
		return c.SendString("Admin access granted")
	})

	// Apply JWT middleware to protected routes
	app.Use("/profile", jwtMiddleware.Middleware())

	// Serve the profile page

	app.Get("/profile", func(c *fiber.Ctx) error {

		type MyCookieParser struct {
			Token string `cookie:"token"`
		}
		p := new(MyCookieParser)
		if err := c.CookieParser(p); err != nil {
			return err
		}
		tokenString := p.Token

		// Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid token")
		}

		// If token is valid, serve the profile page
		return c.SendFile("profile.html")
	})

	// Handle fetching user info (for authenticated user only)
	app.Get("/profile/info", func(c *fiber.Ctx) error {
		userIDStr := c.Query("userid")
		if userIDStr == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Missing userID parameter")
		}

		// Convert userID to int
		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString("Invalid userid parameter")
		}

		var username string
		err = db.QueryRow("SELECT username FROM user WHERE id = ?", userID).Scan(&username)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to retrieve user info")
		}

		return c.JSON(fiber.Map{
			"userID":   userID,
			"username": username,
		})
	})

	app.Listen(":3030")

}
