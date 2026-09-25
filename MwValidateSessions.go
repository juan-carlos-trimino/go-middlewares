package middlewares

import (
  "crypto/subtle"
  "encoding/base64"
  "encoding/json"
  "errors"
  "fmt"
  "net/http"
  "strconv"
  "strings"
  "time"
  //Importing the sessions package with alias "sess".
  sess "github.com/juan-carlos-trimino/go-sessions"
)

//Protect private pages.
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
      //Invalid cookie format.
      cookie.Value = ""  //Zero out the value for safety.
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
      cookie.Value = ""  //Zero out the value for safety.
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
      cookie.Value = ""  //Zero out the value for safety.
      cookie.MaxAge = -1  //Instruct the browser to delete immediately.
      http.SetCookie(res, cookie)
      http.Redirect(res, req, "/login", http.StatusSeeOther)
      return
    }
    //** 5. Database Check: Does the token still actively reside inside Redis? **
    //Remote Server-Side Expiration Test (Secure).
    jsonBytes, err := sess.GetRedis(req.Context(), sessionId)
    if err != nil {
      cookie.Value = ""  //Zero out the value for safety.
      cookie.MaxAge = -1  //Instruct the browser to delete immediately.
      http.SetCookie(res, cookie)
      if errors.Is(err, sess.ErrKeyNotFound) {
        http.Redirect(res, req, "/login", http.StatusSeeOther)
        return
      }
      //Handle unexpected database system crashes (500).
      http.Error(res, "Internal Server Error", http.StatusInternalServerError)
      return
    }
    var sessionInfo sess.SessionInfo
    if err := json.Unmarshal(jsonBytes, &sessionInfo); err != nil {
      sess.DelRedis(req.Context(), sessionId)
      cookie.Value = ""  //Zero out the value for safety.
      cookie.MaxAge = -1  //Instruct the browser to delete immediately.
      http.SetCookie(res, cookie)
      http.Error(res, "Internal Server Error", http.StatusInternalServerError)
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
      if err != nil {
        /***
        If you pull the cookie directly out of the request via req.Cookie(name), change only its MaxAge field to -1, and pass
        it back to http.SetCookie, it will work perfectly because the Name and Path are already inherently correct.
        ***/
        cookie.Value = ""  //Zero out the value for safety.
        cookie.MaxAge = -1  //Instruct the browser to delete immediately.
        http.SetCookie(res, cookie)
        http.Error(res, "Internal Server Error", http.StatusInternalServerError)
        return
      } else if !ok {
        cookie.Value = ""  //Zero out the value for safety.
        cookie.MaxAge = -1  //Instruct the browser to delete immediately.
        http.SetCookie(res, cookie)
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
      var (
        isValid = false  //A tracker flag to determine if validation succeeded.
        errMessage string
        errCode int
      )
      /***
      In Go, closures capture outer variables by reference, not by value. This means the unnamed function is not looking at a
      snapshot or copy of the variable -- it is looking at the exact same memory location as the outer function.

      Because it shares the exact same variable, any changes made to that variable outside the function will be seen inside the
      function, and vice versa.
      ***/
      //Define a reusable cleanup routine to clear state on failure.
      invalidSession := func() {  //Lambda.
        //Instantly delete the key from Redis using your namespace pattern.
        sess.DelRedis(req.Context(), "session:" + sessionId)
        //Clear the browser cookie by setting MaxAge to -1.
        cookie.Value = ""  //Zero out the value for safety.
        cookie.MaxAge = -1
        http.SetCookie(res, cookie)
      }
      //Ensure cleanup executes automatically if a failure triggers a premature return.
      defer func() {
        if !isValid {
          //Call the cleanup routine which sets the cookie first.
          invalidSession()
          //Now that the cookie is safely attached to the headers, write the HTTP error code.
          http.Error(res, errMessage, errCode)
        }
      }()
      //Parse the incoming form payload.
      if err := req.ParseForm(); err != nil {
        errMessage = "Bad Request: Failed to parse form"
        errCode = http.StatusBadRequest
        return  //Triggers defer -> invalidSession() sets cookie -> http.Error writes headers.
      }
      //Read the token directly from the hidden form body element.
      incomingCSRF := req.PostFormValue("csrf_token")
      //Quick sanity check for missing tokens.
      if incomingCSRF == "" {
        errMessage = "Forbidden: CSRF Token Missing"
        errCode = http.StatusForbidden
        return  //Triggers defer -> invalidSession() sets cookie -> http.Error writes headers.
      }
      //Decode the incoming browser token back to original raw bytes.
      rawIncomingBytes, err := base64.URLEncoding.DecodeString(incomingCSRF)
      if err != nil {
        errMessage = "Forbidden: Malformed CSRF Token Encoding"
        errCode = http.StatusForbidden
        return  //Triggers defer -> invalidSession() sets cookie -> http.Error writes headers.
      }
      //Decode the stored token out of your Redis session struct back to original raw bytes.
      rawStoredBytes, err := base64.StdEncoding.DecodeString(sessionInfo.CSRFToken)
      if err != nil {
        errMessage = "Internal Server Error"
        errCode = http.StatusInternalServerError
        return  //Triggers defer -> invalidSession() sets cookie -> http.Error writes headers.
      }
      //Perform a constant-time comparison on the raw cryptographic messages.
      if subtle.ConstantTimeCompare(rawIncomingBytes, rawStoredBytes) != 1 {
        errMessage = "Forbidden: CSRF Token Invalid"
        errCode = http.StatusForbidden
        return  //Triggers defer -> invalidSession() sets cookie -> http.Error writes headers.
      }
      //If code execution reaches this point, the request is valid!
      isValid = true
    }
    //Proceed to handler without executing a single Redis call if time left > session timeout.
    handler.ServeHTTP(res, req)
  }
}
