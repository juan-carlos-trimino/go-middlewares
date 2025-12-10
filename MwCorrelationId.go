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
    cId := req.Header.Get("X-Correlation-Id")
    if cId == "" {
      //The header is not present in the request, generate a new unique id.
      cId = uuid.New().String()
    }
    //Creating a new context from a parent context.
    ctx := context.WithValue(req.Context(), correlationIdKey, cId)
    ctx = context.WithValue(ctx, startTimeKey, time.Now())
    //Add the correlation id to the response header.
    res.Header().Set("X-Correlation-Id", cId)
    //Calling the handler with the new context.
    handler.ServeHTTP(res, req.WithContext(ctx))
  }
}
