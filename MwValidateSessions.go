package middlewares

/***
Create repo and clone it.
$ git clone git@github.com:juan-carlos-trimino/go-middlewares.git

Initialize Go.
$ cd go-middlewares
Execute "go mod init github.com/{GitHub-Username}/{Repo-Name}
$ go mod init github.com/juan-carlos-trimino/go-middlewares

Create the file "main.go" and add the code to it.

Commit and push the code.
$ git add .
$ git commit -m "initial commit."
$ git push origin main

Go uses "Git Tags" to manage versions of the code. Create the tag and push it.
When code is pushed to the repo, repeat these two steps; ensure the version is changed accordingly.
$ git tag "v1.0.0"
$ git push origin main --tags

To use the package, install it (go get -u {copy the repo url from GitHub}).
$ go get -u github.com/juan-carlos-trimino/go-middlewares

Next, open the file that will use the package and add this line
("github.com/{GitHub-Username}/{Repo-Name}").

import "github.com/juan-carlos-trimino/go-middlewares"

To upgrade/downgrade the version of the package, move to the root of the module's directory
structure (where the go.mod file is located) and execute
(go get -u "{package-name}@{git-commit-hash}").
$ go get -u "github.com/juan-carlos-trimino/go-middlewares@xxxxxxx"
***/

import (
	"context"
	"net/http"

	sessions "github.com/juan-carlos-trimino/gpsessions"
)

// Protect private pages.
func ValidateSessions(handler http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var ctx context.Context
		cookie, err := req.Cookie("session_token")
		if err != nil {
			ctx = context.WithValue(req.Context(), sessionTokenKey, "")
		} else if exists := sessions.SessionExists(cookie.Value); !exists {
			ctx = context.WithValue(req.Context(), sessionTokenKey, "")
			//If the session token is present, but has expired, delete the session and return
			//an unauthorized status.
		} else if sessions.IsSessionExpired(cookie.Value) {
			ctx = context.WithValue(req.Context(), sessionTokenKey, "")
		} else if req.Method == http.MethodPost {
			csrf := req.PostFormValue("csrf_token")
			if !sessions.CompareUuids(csrf, cookie.Value) {
				ctx = context.WithValue(req.Context(), sessionTokenKey, "")
			} else {
				//ctx = context.WithValue(context.Background(), sessionStatusKey, true)
				//ctx = context.WithValue(ctx, sessionTokenKey, cookie.Value)
				ctx = context.WithValue(req.Context(), sessionTokenKey, cookie.Value)
			}
		} else {
			ctx = context.WithValue(req.Context(), sessionTokenKey, cookie.Value)
		}
		handler.ServeHTTP(res, req.WithContext(ctx))
	}
}
