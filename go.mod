//Uninstalling a library (or module) from a Go project primarily involves managing the go.mod file
//and the module cache.
//(1) Remove the Dependency from go.mod
//    The first step is to remove the line corresponding to the library you want to uninstall from
//    your project's go.mod file. This file lists all the direct dependencies of your module.
//(2) Run go mod tidy
//    After removing the dependency from go.mod, execute the following command in your terminal
//    within your project's root directory:
//    $ go mod tidy
//
//The default name for the generated executable would be:
module github.com/juan-carlos-trimino/go-middlewares

go 1.26.4

require (
	github.com/google/uuid v1.6.0
	github.com/juan-carlos-trimino/go-logger v0.0.0-20261030024803-de98fdc9cf37
	github.com/juan-carlos-trimino/go-sessions v0.0.0-20261030024906-3956e157ed9f
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/redis/go-redis/v9 v9.22.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
