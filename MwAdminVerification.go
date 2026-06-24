package middlewares

import (
  "context"
  //Run this command in your terminal to install the standard JWT library for Go:
  // $ go get -u github.com/golang-jwt/jwt/v5
  "github.com/golang-jwt/jwt/v5"
  "net/http"
  "strings"
  "time"
)

// Use a secure environment variable for this in production!
var jwtSecretKey = []byte("your_ultra_secure_secret_key_here")

/***
JWT Structure.
A JWT consists of three parts base64-encoded and separated by dots: Header.Payload.Signature
1. The header identifies the algorithm used for signing.
2. The payload contains claims about the user like ID, roles, and expiration time.
3. The signature verifies the token hasn't been tampered with.
***/
func AdminVerification(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    //Extract token from Authorization header (Authorization: Bearer eyJhbGciOiJIUzI1Ni...).
    authHeader := req.Header.Get("Authorization")
    if authHeader == "" {
      http.Error(res, "Authorization header required: ", http.StatusUnauthorized)
      return
    }
    parts := strings.Split(authHeader, " ")  //Split "Bearer <token>".
    //Case-insensitive check.
    if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
      http.Error(res, "Invalid Authorization format: ", http.StatusUnauthorized)
      return
    }
    claims, err := validateJwtToken(parts[1])
    if err != nil {
      http.Error(res, "Invalid or expired token: ", http.StatusUnauthorized)
      return
    }
    //Extract information from claim and enforce admin privileges.
    var isAdmin bool = claims["is_admin"].(bool)
    if !isAdmin {
      http.Error(res, "Forbidden: Admins only: ", http.StatusForbidden)
      return
    }
    //Creating a new context from a parent context.
    ctx := context.WithValue(req.Context(), adminVerificationKey, isAdmin)
    //Calling the handler with the new context.
    handler.ServeHTTP(res, req.WithContext(ctx))
  }
}

/***
Verification of JWT.
1. Extraction: The server retrieves the token from the incoming HTTP request (usually from the Authorization: Bearer <token> header
   or a secure cookie).
2. Signature Re-calculation: The server extracts the Header and Payload from the token, joins them, and hashes them using the algorithm
   specified in the header and the server's private/secret key. If this newly generated signature matches the signature attached to the
   token, it proves the payload has not been tampered with.
3. Claims Validation: Once the signature is proven authentic, the server evaluates standard time-based fields embedded in the payload,
   ensuring the current time is before the expiration time and after the "not before" time.
***/
func validateJwtToken(tokenString string) (jwt.MapClaims, error) {
  token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    /***
    Verify signature algorithm is HMAC. Without this check, an attacker could change the token header to {"alg": "none"} or exploit a
    "Symmetric-Asymmetric Key Confusion" vulnerability to bypass security entirely.
    ***/
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
      return nil, jwt.ErrSignatureInvalid
    }
    //Return the secret key used to verify the signature.
    return jwtSecretKey, nil
  })
  if err != nil {
    return nil, err
  }
  //Extract and validate claim.
  if claim, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
    return claim, nil
  }
  return nil, jwt.ErrTokenUnverifiable
}

/***
By default, standard JWTs are signed, not encrypted. This means anyone who intercepts the token can decode and read its payload contents.
A common point of confusion is thinking that JWT data are hidden.
Data is public: Standard JWTs are base64-encoded, not encrypted. Anyone who intercepts the token can read the content inside the payload.
Tamper-proof, not secret: The security of a JWT relies entirely on its signature. The server uses a secret key to sign the token. If a
malicious actor modifies the payload, the signature becomes invalid, and it will be rejected.
***/
func GenerateJwtToken(is_admin bool) (string, error) {
  //JSON Web Tokens require times -- such as expiration (exp) or issued-at (iat) -- to be encoded as a Unix epoch timestamp in seconds.
  claim := jwt.MapClaims{
    "is_admin": is_admin,
    // "iss": "self",  //Issuer - Who issued the token.
    // "aud": []string{"self"},  //Audience - Who the token is intended for.
    "exp": jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),  //Expires at - When the token expires.
    "iat": jwt.NewNumericDate(time.Now()),  //Issued at - When the token was issued.
    "nbf": jwt.NewNumericDate(time.Now()),  //Not before - When the token becomes valid.
  }
  //Declare signing method HS256.
  token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
  //Cryptographically hashes the combined header and payload using the secret key via the standard HMAC-SHA256 (HS256) protocol.
  tokenString, err := token.SignedString(jwtSecretKey)
  if err != nil {
    return "", err
  }
  return tokenString, nil
}
