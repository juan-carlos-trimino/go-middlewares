package middlewares

import (
  "context"
  "crypto/subtle"
  "encoding/base64"
  "encoding/json"
  "errors"
  "net/http"
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
    switch lowerPath {
    case "/",
         "/login",
         "/favicon.ico":
      handler.ServeHTTP(res, req)
      return
    case "/verify_login":
      if req.Method == http.MethodPost {
        handler.ServeHTTP(res, req)
      } else {
        http.Redirect(res, req, "/login", http.StatusSeeOther)
      }
      return
    default:
      break
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
    sessionId, expiryUnix, err := sess.VerifyAndSplitCookie(cookie.Value)
    if err != nil {
      /***
      If a malicious actor alters a cookie or sends a completely broken string (like session_token=garbage), VerifyAndSplitCookie returns an error, meaning sessionId will be an empty string "". Your code then attempts to call sess.DelRedis(context.Background(), "session:"). This means you will execute a delete operation on your namespace root or pass a malformed key to Redis.

      Since a bad signature means the cookie cannot be trusted or identified, do not try to wipe a session out of Redis. Skip DelRedis entirely here and just call invalidSession to drop the bad client-side cookie file.
      ***/
      invalidSession(res, req, false)
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
      sess.DelRedis(context.Background(), "session:" + sessionId)
      //Continue with or without error to ensure the client-side cookie is deleted.
      //Session expired.
      invalidSession(res, req, false)
      return
    }
    //** 5. Database Check: Does the token still actively reside inside Redis? **
    //Remote Server-Side Expiration Test (Secure).
    jsonBytes, err := sess.GetRedis(req.Context(), "session:" + sessionId)
    if err != nil {
      if errors.Is(err, sess.ErrKeyNotFound) {
        invalidSession(res, req, false)
        return
      }
      sess.DelRedis(context.Background(), "session:" + sessionId)
      //Cannot delete the entry for "user:data:" since we do not have the username!!!
      //Handle unexpected database system crashes (500).
      invalidSession(res, req, true)
      return
    }
    var sessionInfo sess.SessionInfo
    if err := json.Unmarshal(jsonBytes, &sessionInfo); err != nil {
      sess.DelRedis(context.Background(), "session:" + sessionId)
      //Cannot delete the entry for "user:data:" since we do not have the username!!!
      invalidSession(res, req, true)
      return
    }
    //** 6. Validate CSRF for POST requests. **
    /***
    By validating the CSRF token before executing the rolling refresh, we have closed a subtle loophole. Attackers can no longer
    force the Redis database to spend resources updating session TTLs using invalid requests.
    ***/
    if req.Method == http.MethodPost {
      /***
      In Go, closures capture outer variables by reference, not by value. This means the unnamed function is not looking at a
      snapshot or copy of the variable -- it is looking at the exact same memory location as the outer function.

      Because it shares the exact same variable, any changes made to that variable outside the function will be seen inside the
      function, and vice versa.
      ***/
      //Define a reusable cleanup routine to clear state on failure.
      failRequest := func(message string, code int) {  //Lambda.
        /***
        In Go's standard http server framework, once a handler completes or returns (which triggers the defer), the underlying
        network context tracking req.Context() begins teardown optimization. If your Redis driver processes the DelRedis request
        asynchronously or right at the edge of the context cancellation pool, the database command might fail silently due to a
        context.Canceled or context.DeadlineExceeded error.

        To resolve the network context teardown issue, we swap req.Context() with context.Background() only inside terminal
        execution flows (like defer blocks, explicit logouts, or sudden errors where execution must complete regardless of
        whether the client dropped the HTTP connection).
        ***/
        //Instantly delete the key from Redis using your namespace pattern.
        sess.DelRedis(context.Background(), "session:" + sessionId)
        sess.DelRedis(context.Background(), "user:data:" + sessionInfo.UserName)
        //Clear the browser cookie by setting MaxAge to -1.
        http.SetCookie(res, sess.CreateCookie("session_token", ""))
        http.Error(res, message, code)  //Safely write headers and response body.
      }
      //Parse the incoming form payload.
      if err := req.ParseForm(); err != nil {
        failRequest("Bad Request: Failed to parse form", http.StatusBadRequest)
        return
      }
      //Read the token directly from the hidden form body element.
      incomingCSRF := req.PostFormValue("csrf_token")
      //Quick sanity check for missing tokens.
      if incomingCSRF == "" {
        failRequest("Forbidden: CSRF Token Missing", http.StatusForbidden)
        return
      }
      //Decode the incoming browser token back to original raw bytes.
      rawIncomingBytes, err := base64.StdEncoding.DecodeString(incomingCSRF)
      if err != nil {
        failRequest("Forbidden: Malformed CSRF Token Encoding", http.StatusForbidden)
        return
      }
      //Decode the stored token out of your Redis session struct back to original raw bytes.
      rawStoredBytes, err := base64.StdEncoding.DecodeString(sessionInfo.CSRFToken)
      if err != nil {
        failRequest("Internal Server Error", http.StatusInternalServerError)
        return
      }
      //Perform a constant-time comparison on the raw cryptographic messages.
      if subtle.ConstantTimeCompare(rawIncomingBytes, rawStoredBytes) != 1 {
        failRequest("Forbidden: CSRF Token Invalid", http.StatusForbidden)
        return
      }
    }
    //** 7. Rolling Refresh: If safe, verify if we crossed the threshold limit. **
    //Fetch the thread-safe synchronized timing configuration.
    timeCfg := sess.GetSessionTimeoutConfig()
    /***
    To implement an "automatic rolling session refresh," you check how much time has passed since the session started. If the time
    remaining falls below your Threshold, you generate a new cookie and reset the TTL in Redis.

    Because your cookie value contains the absolute expiration time (sessionId|expiresAtUnix), you can easily figure out exactly
    how much time is left without hitting Redis first.
    ***/
    if timeLeft < timeCfg.Threshold {  //If remaining time is less than the threshold.
      //If the user is active, reset the countdown clock back to the session timeout.
      //Enforce strict validation on the critical session key
      ok, err := sess.ExpireRedis(req.Context(), "session:" + sessionId, timeCfg.Timeout)
      if err != nil || !ok {
        sess.DelRedis(context.Background(), "user:data:" + sessionInfo.UserName)
        invalidSession(res, req, err != nil)
        return
      }
      /***
      If the user data cache expired or vanished from Redis memory, but the session key itself is still valid, the safest and
      most seamless user experience is to let the request pass through, and simply let the downstream endpoints re-fetch that
      data from PostgreSQL as needed.
      ***/
      //Attempt to extend user data cache. If it fails or is missing, log it but don't disrupt the user; downstream handlers
      //can re-populate it.
      _, _ = sess.ExpireRedis(req.Context(), "user:data:" + sessionInfo.UserName, timeCfg.Timeout)
      /***
      Since the cookie name remains exactly the same and only the value changes, you do not need to send a separate deletion
      cookie at all.

      When you create the new cookie with the updated value and send it via http.SetCookie, the browser matches it up by its
      Name and Path. It will instantly overwrite the old value on disk with your new value.
      ***/
      //Update the Cookie expiration to match Redis.
      sessionExpiresAt := time.Now().Add(timeCfg.Timeout)
      //Convert "uuid|timestamp" into "uuid|timestamp|signature".
      newCookie := sess.CreateCookie("session_token", sess.SignCookieValue(sessionId, sessionExpiresAt.Unix()))
      newCookie.MaxAge = int(timeCfg.Timeout.Seconds())
      newCookie.Expires = sessionExpiresAt
      //Write updated cookie back to the browser.
      http.SetCookie(res, newCookie)
      /***
      Match the Lifetimes Exactly
      If the ValidateSessions middleware is responsible for refreshing the primary cookie, we should have it refresh the Admin
      JWT at the exact same time. For this to work smoothly without complex multi-cookie tracking, make their raw lifespans match:
      * Session Timeout: 30 minutes
      * JWT Expiration (exp): 30 minutes
      When the primary session crosses the threshold, we will check if an admin_token cookie is present. If it is, we will decode
      it to check if it is an admin, generate a brand new JWT token with an extended 30-minute expiration, and attach it to the
      headers right alongside the fresh primary session cookie.

      Why this approach keeps the app stable and secure:
      * Zero Ghost Lockouts: Because both cookies extend their lifespans simultaneously during active page navigation, a user working
        continuously will never have their JWT drop out from underneath him.
      * Safe Isolation: We gracefully ignore parsing failures or missing cookies during the refresh step. If a standard user doesn't
        have an admin_token, the block safely skips the JWT generation and continues refreshing its standard session seamlessly.
      * Maintained Integrity: By decoding the current token via the existing secure ValidateJwtToken method first, we ensure that we
        only extend privileges for a user who actually holds a fully valid, untampered admin credential.
      ***/
      //Synchronize the Admin JWT Cookie if it exists.
      if adminCookie, err := req.Cookie("admin_token"); err == nil && adminCookie.Value != "" {
        //Parse the existing token just to securely verify its current admin status.
        if claims, err := sess.ValidateJwtToken(adminCookie.Value); err == nil {
          if isAdmin, ok := claims["is_admin"].(bool); ok && isAdmin {
            //Generate a fresh JWT string extending its lifetime by another x minutes
            newJwt, err := sess.GenerateJwtToken(true)
            if err == nil {
              //Build and attach the fresh active admin cookie mirroring the active parameters.
              newAdminCookie := sess.CreateCookie("admin_token", newJwt)
              sessionExpiresAt = time.Now().Add(timeCfg.Timeout)
              newAdminCookie.MaxAge = int(timeCfg.Timeout.Seconds())
              newAdminCookie.Expires = sessionExpiresAt
              http.SetCookie(res, newAdminCookie)
            }
          }
        }
      }
    }
    ck := MwContextKey{}
    ctx := ck.WithSessionInfo(req.Context(), sessionInfo)
    //Proceed to handler without executing a single Redis call if time left > session timeout.
    handler.ServeHTTP(res, req.WithContext(ctx))
  }
}

func invalidSession(res http.ResponseWriter, req *http.Request, isError bool) {
  http.SetCookie(res, sess.CreateCookie("session_token", ""))
  if isError {
    http.Error(res, "Internal Server Error", http.StatusInternalServerError)
  } else {
    http.Redirect(res, req, "/login", http.StatusSeeOther)
  }
}
