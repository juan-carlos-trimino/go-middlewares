package middlewares

import (
  "net/http"
)

/***
The Content-Security-Policy HTTP response header field is the preferred mechanism for delivering a policy from a server to a client.

Send HTTP HEAD request with curl:
$ curl --verbose -I http://localhost:8080
$ curl --verbose -k -I https://localhost:8443
$ curl --verbose --insecure -I https://localhost:8443
$ curl --verbose --head http://localhost:8080
$ curl --verbose -k --head https://localhost:8443
***/
func SecurityHeaders(handler http.HandlerFunc) http.HandlerFunc {
  return func(res http.ResponseWriter, req *http.Request) {
    /***
    You must manipulate the headers before you execute the inner handler.
    SET SECURITY HEADERS FIRST (Before running the handler)
    Switching from .Add() to .Set() overrides previous defaults cleanly instead of appending values onto an array slice.
    ***/
    /***
    In order to make the server more secure, it is recommended that security headers be added to each response.

    HTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect websites against protocol downgrade
    attacks (https://en.wikipedia.org/wiki/Downgrade_attack) and cookie hijacking
    (https://owasp.org/www-community/attacks/Session_hijacking_attack). For an explanation, see
    https://blog.appcanary.com/2017/http-security-headers.html#hsts.
    max-age = 365 days.
    ***/
    res.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubdomains; preload")
    /***
    For more information about Content Security Policy (HTTP Security Headers), see
    https://blog.appcanary.com/2017/http-security-headers.html
    https://web.dev/articles/csp#inline-code-considered-harmful
    https://content-security-policy.com/

    This HTML tag is a Content Security Policy (CSP) that restricts resource loading to your own domain and specific Google Fonts URLs.
    default-src 'self': It blocks all scripts, images, connect requests, and other unlisted assets unless they come from your own
    website domain.
    style-src 'self' https://fonts.googleapis.com: It allows CSS stylesheets from your site and Google Fonts.
    font-src 'self' https://fonts.gstatic.com: It allows your page to download the actual binary font files (woff2).
    Safety: It is safe from a security standpoint because it restricts external code execution.
    ***/
    res.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; " +
      "connect-src 'self'; img-src 'self'; frame-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; " +
      "font-src 'self' https://fonts.gstatic.com;")
    /***
    In modern browsers, X-XSS-Protection has been deprecated in favor of the Content-Security-Policy to disable the use of inline JavaScript.
    Its use can introduce XSS vulnerabilities in otherwise safe websites. This should not be used unless you need to support older web browsers
    that don't yet support CSP. For an explanation, see https://blog.appcanary.com/2017/http-security-headers.html#x-xss-protection
    ***/
    res.Header().Set("X-XSS-Protection", "1; mode=block")
    /***
    X-Frame-Options is an HTTP header that allows sites control over how your site may be framed within an iframe. Clickjacking is a practical
    attack that allows malicious sites to trick users into clicking links on your site even though they may appear to not be on your site at
    all. For an explanation, see https://blog.appcanary.com/2017/http-security-headers.html#x-frame-options
    ***/
    res.Header().Set("X-Frame-Options", "DENY")
    /***
    The Referrer-Policy HTTP header governs which referrer information, sent in the Referer header, should be included with requests made. The
    "strict-origin-when-cross-origin" sends a full URL when performing a same-origin request, only sends the origin of the document to a-priori
    as-much-secure destination (HTTPS->HTTPS), and sends no header to a less secure destination (HTTPS->HTTP). For an explanation, see
    https://blog.appcanary.com/2017/http-security-headers.html#referrer-policy
    ***/
    res.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
    /***
    Setting this header will prevent the browser from interpreting files as something else than declared by the content type in the HTTP headers.
    Without this header, browsers can incorrectly detect files as scripts and stylesheets, leading to XSS attacks. For an explanation, see
    https://blog.appcanary.com/2017/http-security-headers.html#x-content-type-options

    ************************************************************************************************************
    * WARNING: If this header is set to 'nosniff', you MUST ENSURE the 'Content-Type' header is set correctly. *
    ************************************************************************************************************
    ***/
    res.Header().Set("X-Content-Type-Options", "nosniff")
    /***
    In responses, a Content-Type header provides the client with the actual content type of the returned content. This header's value may be
    ignored, for example when browsers perform MIME sniffing; set the X-Content-Type-Options header value to nosniff to prevent this behavior.

    You must not force text/html on every asset; instead, let Go's built-in file server handle the media types naturally, or explicitly
    override it only if it is missing.
    ***/
    // if res.Header().Get("Content-Type") == "" {
    //   res.Header().Set("Content-Type", "text/html; charset=UTF-8")
    // }
    handler.ServeHTTP(res, req)
  }
}
