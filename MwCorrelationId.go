package middlewares

import (
  "fmt"
  //go get -u github.com/juan-carlos-trimino/go-logger"
  "github.com/juan-carlos-trimino/go-logger"
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
    //Add the correlation id to the response header.
    res.Header().Set("X-Correlation-Id", cId)
    //Captured LOCALLY. Used ONLY by the defer statement below.
    startTime := time.Now()
    logger.LogInfo(fmt.Sprintf("Initialized routing trace at %s.", startTime.UTC().Format(time.RFC3339Nano)), cId)
    /***
    By wrapping the tracking execution in a single defer statement, we ensure that every single request to the server automatically
    calculates its duration and logs it when it finishes. This eliminates the need to manually add boilerplate logging code inside
    every page handler. Because startTime := time.Now() is executed at the absolute top of the middleware chain, the duration
    calculation captures the entire request journey.

    In Go, closures capture outer variables by reference, not by value. This means the unnamed function is not looking at a
    snapshot or copy of the variable -- it is looking at the exact same memory location as the outer function.

    Because it shares the exact same variable, any changes made to that variable outside the function will be seen inside the
    function, and vice versa.
    ***/
    //This executes right as this specific request finishes and leaves the middleware.
    defer func() {  //Lambda.
      //Calculate high-precision millisecond floating points (e.g., 1.45ms)
      duration := float64(time.Since(startTime).Nanoseconds()) / 1e6  //1,000,000 (one million) nanoseconds = 1 millisecond.
      //Log the completed trace information universally.
      logger.LogInfo(fmt.Sprintf("[%s] %s %s took %.5fms", req.Method, req.URL.Path, req.Proto, duration), cId)
    }()
    //Calling the handler with the new context.
    handler.ServeHTTP(res, req.WithContext(ctx))
  }
}
