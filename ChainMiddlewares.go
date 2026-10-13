//To fold all block comments:
//  Ctrl+K and Ctrl+/
//To unfold all block comments:
//  Ctrl+K and Ctrl+J
//
//Build constraint: Only include this file in the build if the target OS is Linux and NOT Windows.
//Note: There must be a blank line between the build constraints and the 'package' keyword.
//go:build linux && !windows

package middlewares

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
