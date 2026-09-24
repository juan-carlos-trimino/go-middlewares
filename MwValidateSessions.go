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
    //** 1. Validate HTTP Method. **
    if req.Method != http.MethodPost && req.Method != http.MethodGet {
      // http.Error(res, "Method not allowed", http.StatusMethodNotAllowed)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    //** 2. Bypass rules: Exclude public paths and the login/welcome endpoints from the session validation logic. **
    //Normalize the URL path to lowercase to safely bypass any case quirks.
    lowerPath := strings.ToLower(req.URL.Path)
    //Check for exact matching.
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
    //Allow ALL files inside the /public/ folder.
    if strings.HasPrefix(lowerPath, "/public/") {
      handler.ServeHTTP(res, req)
      return
    }
    //** 3. Extract cookie (assuming it contains: "uuid|timestamp"). **
    cookie, err := req.Cookie("session_token")
    if err != nil {
      //Unauthorized.
      http.Redirect(res, req, "/login", http.StatusSeeOther)  //No cookie found.
      return
    }
    parts := strings.Split(cookie.Value, "|")
    if len(parts) != 2 {
      //Malformed or tampered cookie layout? Route to login page immediately.
      //Invalid cookie format
      cookie.MaxAge = -1  //Instruct the browser to delete immediately.
      http.SetCookie(res, cookie)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    sessionId := parts[0]
    expiryUnix, err := strconv.ParseInt(parts[1], 10 /*base*/, 64 /*int64*/)
    if err != nil {
      sess.DelRedis(req.Context(), sessionId)
      //Continue with or without error to ensure the client-side cookie is deleted.
      //Invalid expiry format.
      cookie.MaxAge = -1  //Instruct the browser to delete immediately.
      http.SetCookie(res, cookie)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    //Convert timestamp and compute how much time is left.
    expiresAt := time.Unix(expiryUnix, 0)
    //Calculate remaining lifetime left on this cookie.
    timeLeft := time.Until(expiresAt)
    //** 4. Local Check: Has the client-side cookie expired? **
    /***
    To test if a session has expired inside your middleware, you must perform two checks: a local timestamp validation (reading
    the cookie value) followed by a database validation (checking Redis).
    ***/
    if time.Now().After(expiresAt) {  //Local Client-Side Expiration Test (Fast & Free).
      /***
      If you confirm a session has expired based on the cookie value, you should call Redis to delete that entry.

      Why you should call Redis to delete the entry
      1. Preventing Session Replay Attacks: Cookies can be copied or intercepted. If an attacker managed to steal that session
         cookie before it expired, and your middleware only checks the time metadata on the cookie, the attacker could manipulate
         their local cookie to alter the expiration timestamp. If you don't check and explicitly evict that session token
         identifier from Redis, the server-side session remains valid and open to hijacking.
      2. Preventing Stale Data Accrual: If your Redis keys do not have a built-in TTL (Time-To-Live) expiration set up when
         created via SETEX or EXPIRE, skipping the delete call means that expired session will sit in your Redis database
         memory forever.
      ***/
      sess.DelRedis(req.Context(), sessionId)
      //Continue with or without error to ensure the client-side cookie is deleted.
      //Session expired.
      cookie.MaxAge = -1  //Instruct the browser to delete immediately.
      http.SetCookie(res, cookie)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    //** 5. Database Check: Does the token still actively reside inside Redis? **
    _, err = sess.GetRedis(req.Context(), sessionId)  //Remote Server-Side Expiration Test (Secure).
    if err != nil {
      /***
      Redis returned redis.Nil (expired) or database down.
      Send back a cookie with MaxAge = -1 and an expired timestamp. This instructs the browser to immediately delete
      the cookie from disk.
      ***/
      cookie.MaxAge = -1  //Instruct the browser to delete immediately.
      http.SetCookie(res, cookie)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    //** 6. Fetch the thread-safe synchronized timing configuration. **
    timeCfg := sess.GetSessionTimeoutConfig()
    //** 7. Rolling Refresh: If safe, verify if we crossed the threshold limit. **
    /***
    To implement an "automatic rolling session refresh," you check how much time has passed since the session started. If the time
    remaining falls below your Threshold, you generate a new cookie and reset the TTL in Redis.

    Because your cookie value contains the absolute expiration time (sessionId|expiresAtUnix), you can easily figure out exactly
    how much time is left without hitting Redis first.
    ***/
    if timeLeft < timeCfg.Threshold {  //If remaining time is less than the threshold.
      //If the user is active, reset the countdown clock back to the session timeout.
      ok, err := sess.ExpireRedis(req.Context(), sessionId, timeCfg.Timeout)
      if err != nil || !ok {
        sess.DelRedis(req.Context(), sessionId)
        //Continue with or without error to ensure the client-side cookie is deleted.
        /***
        If you pull the cookie directly out of the request via req.Cookie(name), change only its MaxAge field to -1, and pass
        it back to http.SetCookie, it will work perfectly because the Name and Path are already inherently correct.
        ***/
        cookie.MaxAge = -1  //Instruct the browser to delete immediately.
        http.SetCookie(res, cookie)
        //If session missing or Redis down, fail safely.
        http.Redirect(res, req, "/login", http.StatusSeeOther)
        return
      }
      /***
      Since the cookie name remains exactly the same and only the value changes, you do not need to send a separate deletion
      cookie at all.

      When you create the new cookie with the updated value and send it via http.SetCookie, the browser matches it up by its
      Name and Path. It will instantly overwrite the old value on disk with your new value.
      ***/
      //Update the Cookie expiration to match Redis.
      sessionExpiresAt := time.Now().Add(timeCfg.Timeout)
      cookie.Value = fmt.Sprintf("%s|%d", sessionId, sessionExpiresAt.Unix())
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
