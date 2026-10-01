package middlewares

import (
  "fmt"
  "net/http"
  //Importing the sessions package with alias "sess".
  sess "github.com/juan-carlos-trimino/go-sessions"
)

/***
JWT Structure.
A JWT consists of three parts base64-encoded and separated by dots: Header.Payload.Signature
1. The header identifies the algorithm used for signing.
2. The payload contains claims about the user like ID, roles, and expiration time.
3. The signature verifies the token hasn't been tampered with.
***/
func AdminVerification(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    /***
    This middleware checks admin_token in total isolation. If a developer accidentally adds AdminVerification to a route but
    forgets to add ValidateSessions, a user with a valid admin cookie could access the route even if their primary Redis session
    was deleted or revoked.

    The Fix: Inside AdminVerification, add a defensive assertion to verify that a primary user session already exists in the
    request context. This guarantees that the middleware sequence cannot be misconfigured out of order.
    ***/
    if req.Context().Value(sessionInfoKey) == nil {
      /***
      We should not delete the Redis session keys inside AdminVerification if the admin token fails validation. Instead, we should
      only delete the admin_token cookie using http.SetCookie.

      An invalid or expired admin_token does not mean the user's core website login is invalid. It usually just means their elevated
      "Admin Session" or "Sudo Mode" has expired. If we wipe out their primary Redis session keys inside AdminVerification, we will
      log the user completely out of the entire application simply because their admin timer ran out. Instead, by only wiping the
      admin_token cookie and throwing an error, the user stays logged in as a normal user. They can then gracefully navigate back to
      a profile or re-authenticate via an admin login prompt without having their entire application state destroyed.

      The Correct Deletion Boundaries
      To keep the system clean, remember this rule of thumb for the two middleware layers:
      * Inside ValidateSessions: If this fails, the core user login is dead. We MUST clear the Redis session keys (session:* and
        user:data:*) and clear the session_token cookie.
      * Inside AdminVerification: If this fails, only the admin privilege is dead. We ONLY clear the admin_token cookie. Leave the
        Redis database untouched.
      ***/
      http.Error(res, fmt.Sprintf("Error %d: ValidateSessions is required.", http.StatusUnauthorized), http.StatusUnauthorized)
      return
    }
    // Extract cookie.
    cookie, err := req.Cookie("admin_token")
    if err != nil {
      http.Error(res, fmt.Sprintf("Error %d: Authorization missing.", http.StatusUnauthorized), http.StatusUnauthorized)
      return
    }
    claims, err := sess.ValidateJwtToken(cookie.Value)
    if err != nil {
      //Clear the broken/expired admin cookie.
      http.SetCookie(res, sess.CreateCookie("admin_token", ""))
      http.Error(res, fmt.Sprintf("Error %d: Invalid or expired token.", http.StatusUnauthorized), http.StatusUnauthorized)
      return
    }
    //Extract information from claim and enforce admin privileges.
    isAdmin, ok := claims["is_admin"].(bool)
    //Check both existence and the explicit boolean data type.
    if !ok || !isAdmin {
      //Clear the broken/expired admin cookie.
      http.SetCookie(res, sess.CreateCookie("admin_token", ""))
      http.Error(res, fmt.Sprintf("Error %d: Admins only.", http.StatusForbidden), http.StatusForbidden)
      return
    }
    //Instantiate the context helper.
    ck := MwContextKey{}
    //Explicitly inject and forward context.
    ctx := ck.WithAdminVerification(req.Context(), isAdmin)
    //Calling the handler with the new context.
    handler.ServeHTTP(res, req.WithContext(ctx))
  }
}
