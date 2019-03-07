package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/satori/go.uuid"
)

func upload(w http.ResponseWriter, req *http.Request) {
	u := getUser(w, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	// tpl.ExecuteTemplate(w, "upload.gohtml", u)
	fmt.Println(u)

	c := getCookie(w, req)
	if req.Method == http.MethodPost {
		//multipart.File, *multipart.FileHeader, error
		mf, fh, err := req.FormFile("file")
		if err != nil {
			fmt.Println(err)
		}

		defer mf.Close()

		ext := strings.Split(fh.Filename, ".")[1]
		// create sha for file name
		h := sha1.New()
		io.Copy(h, mf)
		fname := fmt.Sprintf("%x", h.Sum(nil)) + "." + ext
		//example: 67f19a7a-0b1f-49a9-ba9b-3f39b843c1df|c2ac15cca4bb13e939ac05cf3e49a8f0818894b4.jpg

		// create new file use working directory
		wd, err := os.Getwd()
		if err != nil {
			fmt.Println(err)
		}
		path := filepath.Join(wd, "public", "uploads", fname)
		// fileSrc := "http://127.0.0.1:8080/uploads/" + fh.Filename

		file, err := os.Create(path)
		if err != nil {
			fmt.Println(err)
		}
		defer file.Close()

		mf.Seek(0, 0)
		io.Copy(file, mf)
		c = appendValue(w, c, fname)
	}
	xs := strings.Split(c.Value, "|")
	// sliced cookie values to only send over images
	tpl.ExecuteTemplate(w, "upload.gohtml", xs[1:])
}

func getCookie(w http.ResponseWriter, req *http.Request) *http.Cookie {
	c, err := req.Cookie("session")
	if err != nil {
		sID, _ := uuid.NewV4()
		c = &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)
	}
	return c
}

//append picture filename to cookie value
func appendValue(w http.ResponseWriter, c *http.Cookie, fname string) *http.Cookie {
	s := c.Value
	if !strings.Contains(s, fname) {
		s += "|" + fname
	}
	c.Value = s
	http.SetCookie(w, c)
	return c
}
