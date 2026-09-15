package middlewares

import (
  "context"
  "net/http"
  // Importing the sessions package with alias "sess"
  sess "github.com/juan-carlos-trimino/go-sessions"
)

/***
// Protect private pages.
func ValidateSessions(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    var ctx context.Context
    cookie, err := req.Cookie("session_token")
    if err != nil {
      ctx = context.WithValue(req.Context(), sessionTokenKey, "")
    } else if exists := sess.SessionExists(cookie.Value); !exists {
      ctx = context.WithValue(req.Context(), sessionTokenKey, "")
      //If the session token is present, but has expired, delete the session and return an unauthorized status.
    } else if sess.IsSessionExpired(cookie.Value) {
      ctx = context.WithValue(req.Context(), sessionTokenKey, "")
    } else if req.Method == http.MethodPost {
      csrf := req.PostFormValue("csrf_token")
      if !sess.CompareUuids(csrf, cookie.Value) {
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
***/



// Protect private pages.
func ValidateSessions(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    cookie, err := req.Cookie("session_token")
    if err != nil {  //No cookie present.
      ctx := context.WithValue(req.Context(), sessionTokenKey, "")
      handler.ServeHTTP(res, req.WithContext(ctx))
      return
    }
    oldToken := cookie.Value

    //BYPASS ROLLING FOR LOGOUT ROUTE
    if req.URL.Path == "/logout" {
      // Put the raw incoming token into the context so LogoutPage can read it directly
      ctx := context.WithValue(req.Context(), sessionTokenKey, oldToken)
      handler.ServeHTTP(res, req.WithContext(ctx))
      return
    }



    if exists := sess.SessionExists(oldToken); !exists {  //Validate session existence.
      ctx := context.WithValue(req.Context(), sessionTokenKey, "")
      handler.ServeHTTP(res, req.WithContext(ctx))
      return
    }
    //If the session token is present but has expired, delete the session.
    if sess.IsSessionExpired(oldToken) {
      sess.DeleteSession(oldToken)
      ctx := context.WithValue(req.Context(), sessionTokenKey, "")
      handler.ServeHTTP(res, req.WithContext(ctx))
      return
    }
    //Validate CSRF for POST requests.
    if req.Method == http.MethodPost {
      csrf := req.PostFormValue("csrf_token")
      //Compare client CSRF to old token.
      if !sess.CompareUuids(csrf, oldToken) {
        ctx := context.WithValue(req.Context(), sessionTokenKey, "")
        handler.ServeHTTP(res, req.WithContext(ctx))
        return
      }
    }
    newToken, newSession := sess.UpdateEntryInSessions(oldToken)
    //Update browser storage with the new token.
    newCookie := sess.CreateCookie(newToken)
    newCookie.Expires = newSession.GetExpiry()
    http.SetCookie(res, newCookie)
    ctx := context.WithValue(req.Context(), sessionTokenKey, newToken)
    handler.ServeHTTP(res, req.WithContext(ctx))
  }
}
