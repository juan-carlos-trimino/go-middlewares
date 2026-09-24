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
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/juan-carlos-trimino/go-sessions v1.0.17-0.20260924021518-f17c0f9e6126
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/juan-carlos-trimino/go-logger v1.0.9 // indirect
	github.com/redis/go-redis/v9 v9.22.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/juan-carlos-trimino/go-sessions => ../go-sessions/
