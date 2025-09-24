package middlewares

import (
  "context"
  //The option -u instructs 'get' to update the module with dependencies.
  //go get -u github.com/google/uuid
  "github.com/google/uuid"
  "net/http"
  "time"
)

func CorrelationId(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    uuid := uuid.New()
    //Creating a new context from a parent context.
    ctx := context.WithValue(req.Context(), correlationIdKey, uuid.String())
    ctx = context.WithValue(ctx, startTimeKey, time.Now())
    //Calling the handler with the new context.
    handler.ServeHTTP(res, req.WithContext(ctx))
  }
}
