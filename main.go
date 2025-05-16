
package main

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int
	Username string
	Password string
}

var (
	db        *sql.DB
	templates *template.Template
)

func main() {
	initDatabase()
	initTemplates()

	r := mux.NewRouter()
	r.PathPrefix("/css/").Handler(http.StripPrefix("/css/", http.FileServer(http.Dir("./static/css"))))

	r.HandleFunc("/", redirectToLogin)
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/register", registerHandler).Methods("GET", "POST")
	r.HandleFunc("/welcome", welcomeHandler).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")

	fmt.Println("Server starting on :8443")
	log.Fatal(http.ListenAndServeTLS("0.0.0.0:8443","cert.pem","key.pem", r))
}

func initDatabase() {
	var err error
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://admin:123123@localhost:5432/np?sslmode=disable"
		fmt.Println("Using default database URL. Set DATABASE_URL for production.")
	}
	db, err = sql.Open("pgx", connStr)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}
	fmt.Println("Connected to PostgreSQL")
}

func initTemplates() {
	templates = template.Must(template.ParseGlob("templates/*.html"))
	templates = template.Must(templates.ParseGlob("static/html/*.html"))
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "login.html", nil)
		return
	}

	err := r.ParseForm()
	if err != nil {
		renderTemplate(w, "login.html", map[string]string{"Error": "Failed to parse form"})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var id int
	var storedHash string
	err = db.QueryRow("SELECT id, password FROM users WHERE username = $1", username).Scan(&id, &storedHash)
	if err != nil {
		renderTemplate(w, "login.html", map[string]string{"Error": "Invalid username or password"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		renderTemplate(w, "login.html", map[string]string{"Error": "Invalid username or password"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "user_id",
		Value:    fmt.Sprintf("%d", id),
		HttpOnly: true,
		Path:     "/",
	})
	http.Redirect(w, r, "/welcome", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "register.html", nil)
		return
	}

	err := r.ParseForm()
	if err != nil {
		renderTemplate(w, "register.html", map[string]string{"Error": "Failed to parse form"})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	if len(password) < 8 {
		renderTemplate(w, "register.html", map[string]string{"Error": "Password must be at least 8 characters"})
		return
	}
	if password != confirm {
		renderTemplate(w, "register.html", map[string]string{"Error": "Passwords do not match"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("password hashing error: %v", err)
		renderTemplate(w, "register.html", map[string]string{"Error": "Internal error. Try again."})
		return
	}

	ctx := context.Background()
	_, err = db.ExecContext(ctx, "INSERT INTO users (username, password) VALUES ($1, $2)", username, string(hashed))
	if err != nil {
		log.Printf("insert error: %v", err)
		renderTemplate(w, "register.html", map[string]string{"Error": "Username already exists or DB error"})
		return
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user_id")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	userID := cookie.Value
	var username string
	err = db.QueryRow("SELECT username FROM users WHERE id = $1", userID).Scan(&username)
	if err != nil {
		log.Printf("user lookup error: %v", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	renderTemplate(w, "welcome.html", map[string]string{"Username": username})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "user_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	err := templates.ExecuteTemplate(w, name, data)
	if err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}
