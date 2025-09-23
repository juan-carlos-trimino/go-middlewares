package middlewares

import (
  "context"
  "fmt"
  //The option -u instructs 'get' to update the module with dependencies.
  //go get -u github.com/google/uuid
  "github.com/google/uuid"
  "github.com/juan-carlos-trimino/gplogger"
  "net/http"
  "time"
)

func CorrelationId(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    start := time.Now()
    uuid := uuid.New()
    //Creating a new context from a parent context.
    ctx := context.WithValue(req.Context(), correlationIdKey, uuid.String())
    ctx = context.WithValue(ctx, startTimeKey, time.Now())
    logger.LogInfo("Issuing correlationId to new request.", fmt.Sprintf("%s", uuid))
    //Calling the handler with the new context.
    handler.ServeHTTP(res, req.WithContext(ctx))
    fmt.Printf("xxxxxRequest took %vms\nRequest correlation id: %s\n",
      time.Since(start).Microseconds(), uuid)
  }
}
