package minion

import (
    "context"
    "github.com/julienschmidt/httprouter"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"
)

// Middleware is an adapter function for http.Handler.
type Middleware func(http.Handler) http.Handler

// pathParams returns the path parameters for r as a map of parameter names to
// parameter values.
func PathParams(r *http.Request) map[string]string {
    ctx := r.Context()
    if params, ok := ctx.Value(ctxKeyPathParams).(map[string]string); ok {
        return params
    } else {
        return map[string]string{}
    }
}

// pathParam returns the value of r's path parameter by name. If the parameter
// name is not found, the empty string is returned.
func PathParam(r *http.Request, name string) string {
    return PathParams(r)[name]
}

// middlewareAdapter is an adapter for h such that each provided Middleware will
// be called before h is handled. The Middleware will be executed in the order
// they are provided.
func middlewareAdapter(h http.Handler, middleware ...Middleware) http.Handler {
    i := len(middleware) - 1
    for ; i >= 0; i-- {
        h = middleware[i](h)
    }
    return h
}

// sameOriginMiddleware checks that the source and target origin are the same.
// This should be used on routes that mutate data (PUT, POST, DELETE) to protect
// against CSRF.
// See https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
func SameOriginMiddleware() Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get the target origin
            // Try the X-Forwarded-Host first in case of a proxy
            targetOrigin := r.Header.Get("X-Forwarded-Host")
            if targetOrigin == "" {
                // Try the Host header next
                targetOrigin = r.Host
            }
            if targetOrigin == "" {
                log.Err("Same origin check failed. No target origin found in request.")
                http.Error(w, "", 400)
                return
            }
            targetOrigin = strings.Split(targetOrigin, ":")[0] // strip the port
            // Get the source origin
            // Check the Referer header first since Origin can contain arbitrary
            // values from proxies like "null", "private", "redacted".
            if sourceOriginUrl, err := url.ParseRequestURI(r.Referer()); err == nil {
                if sourceOriginUrl.Hostname() == targetOrigin {
                    log.Info("Same origin check passed using Referer header.")
                    next.ServeHTTP(w, r)
                    return
                }
            }
            // Check the Origin header
            origin := r.Header.Get("Origin")
            if sourceOriginUrl, err := url.ParseRequestURI(origin); err != nil {
                log.Errf("Failed to parse the URL in the Origin header. %s", err.Error())
                http.Error(w, "", 400)
                return
            } else {
                if sourceOriginUrl.Hostname() == targetOrigin {
                    log.Info("Same origin check passed using Origin header.")
                    next.ServeHTTP(w, r)
                    return
                } else { // Cross-origin request
                    log.Err("Same origin check failed.")
                    http.Error(w, "", 400)
                    return
                }
            }
        })
    }
}

func pathParamMiddleware(router *httprouter.Router) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // add the path params to the request context
            method := r.Method
            path := r.URL.Path
            _, params, _ := router.Lookup(method, path)
            ctx := r.Context()
            pathparams := map[string]string{}
            for _, param := range params {
                pathparams[param.Key] = param.Value
            }
            ctx = context.WithValue(ctx, ctxKeyPathParams, pathparams)
            r = r.WithContext(ctx)
            next.ServeHTTP(w, r)
        })
    }
}

func LogMiddleware() Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            b, err := httputil.DumpRequest(r, true)
            if err != nil {
                log.Errf("Unable to dump request: %s", err.Error())
                http.Error(w, "", 500)
                return
            }
            log.Infof("%s", b)
            next.ServeHTTP(w, r)
        })
    }
}
