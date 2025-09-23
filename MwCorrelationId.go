package middlewares

import (
  "context"
  "fmt"
  "net/http"

  //The option -u instructs 'get' to update the module with dependencies.
  //go get -u github.com/google/uuid
  "time"

  "github.com/google/uuid"
)

func CorrelationId(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    start := time.Now()
    uuid := uuid.New()
    //Creating a new context from a parent context.
    ctx := context.WithValue(req.Context(), correlationIdKey, uuid.String())
    ctx = context.WithValue(ctx, startTimeKey, time.Now())
    fmt.Printf("%s *** Issuing correlationId to new request. %s\n", datetimeFormat(), uuid)
    //Calling the handler with the new context.
    handler.ServeHTTP(res, req.WithContext(ctx))
    fmt.Printf("xxxxxRequest took %vms\nRequest correlation id: %s\n",
      time.Since(start).Microseconds(), uuid)
  }
}

func datetimeFormat() string {
  //time.Now() returns the current local time; using the current time in UTC.
  return time.Now().UTC().Format(time.RFC3339Nano)
}
