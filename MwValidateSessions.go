package middlewares

import (
  "context"
  "fmt"
  "net/http"
  // Importing the sessions package with alias "sess"
  sess "github.com/juan-carlos-trimino/go-sessions"
  "strconv"
  "strings"
  "time"
)

//Protect private pages.
/***
func xValidateSessions(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    cookie, err := req.Cookie("session_token")
    if err != nil {  //No cookie present.
      ctx := context.WithValue(req.Context(), sessionTokenKey, "")
      handler.ServeHTTP(res, req.WithContext(ctx))
      return
    }
    oldToken := cookie.Value
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
***/

func ValidateSessions(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    //Validate HTTP Method.
    if req.Method != http.MethodPost && req.Method != http.MethodGet {
      // http.Error(res, "Method not allowed", http.StatusMethodNotAllowed)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    //Normalize the URL path to lowercase to safely bypass any case quirks.
    lowerPath := strings.ToLower(req.URL.Path)
    //Exclude public paths and the login/welcome endpoints from the session validation logic.
    //Check for exact matching static pages.
    if lowerPath == "/" || lowerPath == "/login" {
      handler.ServeHTTP(res, req)
      return
    }
    //
    if lowerPath == "/verify_login" {
      if req.Method == http.MethodPost {
        handler.ServeHTTP(res, req)
      } else {
        // http.Error(res, "Method not allowed", http.StatusMethodNotAllowed)
        http.Redirect(res, req, "/login", http.StatusSeeOther)
      }
      return
    }
    //Dynamic Asset Bypass: Allow ALL files inside the /public/ folder.
    if strings.HasPrefix(lowerPath, "/public/") {
      handler.ServeHTTP(res, req)
      return
    }
    //Extract cookie (assuming it contains: "uuid|timestamp").
    cookie, err := req.Cookie("session_token")
    if err != nil {
      // http.Error(res, "Unauthorized", http.StatusUnauthorized)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    parts := strings.Split(cookie.Value, "|")
    if len(parts) != 2 {
      // http.Error(res, "Invalid cookie format", http.StatusBadRequest)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    sessionId := parts[0]
    expiryUnix, err := strconv.ParseInt(parts[1], 10 /*base*/, 64 /*int64*/)
    if err != nil {
      // http.Error(res, "Invalid expiry format", http.StatusBadRequest)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    //Convert timestamp and compute how much time is left.
    expiresAt := time.Unix(expiryUnix, 0)
    //Calculate remaining lifetime left on this cookie.
    timeLeft := time.Until(expiresAt)
    timeCfg := sess.GetSessionConfig()

    /***
    To test if a session has expired inside your middleware, you must perform two checks: a local timestamp validation (reading
    the cookie value) followed by a database validation (checking Redis).

    Local Client-Side Expiration Test (Fast & Free).
    ***/
    if time.Now().After(expiresAt) {
      // The cookie's timestamp has passed the current time!
      // http.Error(res, "Session expired", http.StatusUnauthorized)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }


    //Remote Server-Side Expiration Test (Secure).
    _, ret := sess.Redis_db.GetRedis(req.Context(), sessionId)
    if ret == 1 {
      http.Error(res, "Unauthorized", http.StatusUnauthorized)
      return
    } else if ret == 2 {
      //Something went wrong communicating with Redis.
      http.Error(res, "Internal server error", http.StatusInternalServerError)
      return
    }


        // 5. Database Check: Does the token still actively reside inside Redis?
    _, err = redis_db.Get(r.Context(), sessionId).Result()
    if err != nil {
      // Redis returned redis.Nil (expired out) or database down
      // Clear the invalid browser cookie so it doesn't loop, then redirect
      clearCookie := &http.Cookie{Name: "session", Path: "/", MaxAge: -1}
      http.SetCookie(w, clearCookie)

      http.Redirect(w, r, "/login", http.StatusSeeOther)
      return
    }



    /***
    To implement an "automatic rolling session refresh," you check how much time has passed since the session started. If the time
    remaining falls below your Threshold, you generate a new cookie and reset the TTL in Redis.

    Because your cookie value contains the absolute expiration time (sessionId|expiresAtUnix), you can easily figure out exactly
    how much time is left without hitting Redis first.
    ***/
    if timeLeft < timeCfg.Threshold {  //If remaining time is less than the threshold.
      //If the user is active, reset the countdown clock back to the session timeout.
      err := sess.Redis_db.Expire(req.Context(), sessionId, timeCfg.Timeout)
      if err != nil {
        //If session missing or Redis down, fail safely.
        // http.Error(res, "Internal server error", http.StatusInternalServerError)
        http.Redirect(res, req, "/login", http.StatusSeeOther)
        return
      }
      //Update browser cookie with a fresh future timestamp.
      sessionExpiresAt := time.Now().Add(timeCfg.Timeout)
      cookieValue := fmt.Sprintf("%s|%d", sessionId, sessionExpiresAt.Unix())
      cookie = sess.CreateCookie(cookieValue)
      //Update the Cookie expiration to match Redis.
      cookie.MaxAge = int(timeCfg.Timeout.Seconds())
      cookie.Expires = sessionExpiresAt
      //Write updated cookie back to the browser.
      http.SetCookie(res, cookie)
    }
    //Validate CSRF for POST requests.
    if req.Method == http.MethodPost {
      csrf := req.PostFormValue("csrf_token")
      //Compare client CSRF to old token.
      if !sess.CompareUuids(csrf, sessionId) {
        ctx := context.WithValue(req.Context(), sessionTokenKey, "")
        handler.ServeHTTP(res, req.WithContext(ctx))
        return
      }
    }
    //Proceed to handler without executing a single Redis call if time left > session timeout.
    handler.ServeHTTP(res, req)
  }
}
