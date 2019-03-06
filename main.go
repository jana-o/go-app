package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	UserName string `json:"userName"`
	Password []byte `json:"password"`
	First    string `json:"first"`
	Last     string `json:"last"`
	ID       int64  `json:"id"`
}

type Photo struct {
	ID  int64  `json:"id"`
	Src string `json:"src"`
}

type PhotoCollection struct {
	Photos []Photo `json:"items"`
}

var tpl *template.Template
var dbUsers = map[string]user{}      // user ID, user
var dbSessions = map[string]string{} // session ID, user ID

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	bs, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	dbUsers["test@test.com"] = user{"test@test.com", bs, "Jana", "O", 1234}
}

func main() {

	// Database
	db := initialiseDatabase("database/database.sqlite")
	migrateDatabase(db)

	//Routes
	http.HandleFunc("/", index)
	// http.HandleFunc("/upload", upload)
	http.HandleFunc("/account", account)
	// http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)

	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("./public"))))
	http.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("./assets"))))
	//using default servemux
	log.Fatal(http.ListenAndServe(":8080", nil))

	fmt.Println("dbUsers:", dbUsers)
}

func index(w http.ResponseWriter, req *http.Request) {
	u := getUser(w, req)
	tpl.ExecuteTemplate(w, "index.html", u)
}

func account(w http.ResponseWriter, req *http.Request) {
	u := getUser(w, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "account.gohtml", u)
}

func signup(w http.ResponseWriter, req *http.Request, db *sql.DB) {
	if alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	var u user
	// process form submission
	if req.Method == http.MethodPost {
		// get form values
		un := req.FormValue("username")
		p := req.FormValue("password")
		f := req.FormValue("firstname")
		l := req.FormValue("lastname")
		// check if user exist
		if _, ok := dbUsers[un]; ok {
			http.Error(w, "Username already taken", http.StatusForbidden)
			return
		}
		// create session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)

		dbSessions[c.Value] = un
		// store user in dbUsers
		bs, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		//save user in DB
		stmt, err := db.Prepare("INSERT INTO users (src) VALUES(?)")
		if err != nil {
			panic(err)
		}

		defer stmt.Close()

		result, err := stmt.Exec(req.FormValue)
		if err != nil {
			panic(err)
		}

		userID, err := result.LastInsertId()
		if err != nil {
			panic(err)
		}

		user := user{
			UserName: un,
			Password: bs,
			First:    f,
			Last:     l,
			ID:       userID,
		}

		// u = user{un, bs, f, l, id}
		dbUsers[un] = user
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "signup.gohtml", u)
}

func login(w http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	var u user
	// process form submission
	if req.Method == http.MethodPost {
		un := req.FormValue("username")
		p := req.FormValue("password")
		// is there a username?
		u, ok := dbUsers[un]
		if !ok {
			http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			return
		}
		// check if password matches stored password
		err := bcrypt.CompareHashAndPassword(u.Password, []byte(p))
		if err != nil {
			http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			return
		}
		// create session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)
		dbSessions[c.Value] = un
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "login.gohtml", u)
}

func logout(w http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	c, _ := req.Cookie("session")
	// delete the session
	delete(dbSessions, c.Value)
	// remove cookie  ____ COOKIE SHOULD NOT BE DELETED!!! ==========
	c = &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)

	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

// Database
func initialiseDatabase(filepath string) *sql.DB {
	db, err := sql.Open("sqlite3", filepath)

	if err != nil || db == nil {
		panic("Error connecting to database")
	}

	return db
}

func migrateDatabase(db *sql.DB) {
	sql := `
        CREATE TABLE IF NOT EXISTS photos(
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                src VARCHAR NOT NULL
        );
   `
	_, err := db.Exec(sql)

	if err != nil {
		panic(err)
	}
}

// func getPhotos(db *sql.DB) *PhotoCollection {

// 	rows, err := db.Query("SELECT * FROM photos")

// 	if err != nil {
// 		panic(err)
// 	}

// 	defer rows.Close()

// 	result := PhotoCollection{}

// 	for rows.Next() {
// 		photo := Photo{}
// 		err2 := rows.Scan(&photo.ID, &photo.Src)

// 		if err2 != nil {
// 			panic(err2)
// 		}

// 		result.Photos = append(result.Photos, photo)
// 	}

// 	return *result

// }
