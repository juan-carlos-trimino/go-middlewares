package middlewares

import (
  "context"
  //Importing the sessions package with alias "sess".
  sess "github.com/juan-carlos-trimino/go-sessions"
)

//To avoid context keys collisions, a best practice is to create an unexported custom type.
type ctxKey int

/***
The correlationIdKey constant is unexported. Hence, there's no risk that another package using the same context could override the value
that is already set. Even if another package creates the same correlationIdKey based on a ctxKey type as well, it will be a different key.
***/
const (
  correlationIdKey ctxKey = iota  //0
  sessionInfoKey  //1
  adminVerificationKey  //2
)

//The public MwContextKey struct provides type-safe accessors for the rest of the application.
type MwContextKey struct{}

/***
Packages that define a Context key should provide type-safe accessors for the values stored using that key.
***/
// --- Correlation ID ---
func (ck MwContextKey) WithCorrelationId(ctx context.Context, cid string) context.Context {
  return context.WithValue(ctx, correlationIdKey, cid)
}

func (ck MwContextKey) GetCorrelationId(ctx context.Context) (cid string, ok bool) {
  //The Value method returns an interface{} so a type assertion is needed. A type assertion is an operation applied to an interface value.
  cid, ok = ctx.Value(correlationIdKey).(string)
  return
}

// --- Session Information ---
func (ck MwContextKey) WithSessionInfo(ctx context.Context, info sess.SessionInfo) context.Context {
  return context.WithValue(ctx, sessionInfoKey, info)
}

func (ck MwContextKey) GetSessionInfo(ctx context.Context) (info sess.SessionInfo, ok bool) {
  //A type assertion is an operation applied to an interface value.
  info, ok = ctx.Value(sessionInfoKey).(sess.SessionInfo)
  return
}

// --- Admin Verification ---
func (ck MwContextKey) WithAdminVerification(ctx context.Context, admin bool) context.Context {
  return context.WithValue(ctx, adminVerificationKey, admin)
}

func (ck MwContextKey) GetAdminVerification(ctx context.Context) (admin bool, ok bool) {
  admin, ok = ctx.Value(adminVerificationKey).(bool)
  return
}
