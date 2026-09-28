package middlewares

import (
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
    //Instantiate the context helper.
    ck := MwContextKey{}
    //Create the new context from the parent using the setter.
    ctx := ck.WithCorrelationId(req.Context(), cId)
    ctx = ck.WithStartTime(ctx, time.Now())
    //Add the correlation id to the response header.
    res.Header().Set("X-Correlation-Id", cId)
    //Calling the handler with the new context.
    handler.ServeHTTP(res, req.WithContext(ctx))
  }
}
