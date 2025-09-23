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
$ go get -u "github.com/juan-carlos-trimino/go-middlewares@b33734a"
or
$ go get -u "github.com/juan-carlos-trimino/go-middlewares@v1.1.0"
***/

import (
  "net/http"
)

type Middleware func(http.HandlerFunc) http.HandlerFunc

func ChainMiddlewares(originalHandler http.HandlerFunc, mw []Middleware) http.HandlerFunc {
  wrapHandler := originalHandler
  length := len(mw)
  for idx := length - 1; idx > -1; idx-- {
    wrapHandler = mw[idx](wrapHandler)
  }
  return wrapHandler
}
