package minion

import (
    "github.com/julienschmidt/httprouter"
    logger "github.com/MattL922/go-logger"
    "net/http"
)

type ctxKey string

const (
    // Context keys
    // These are used as request context keys. They are set up as string aliases
    // to prevent collisions with string keys from other packages.
    ctxKeyPathParams ctxKey = "pathparams"
)

var log = logger.New()

type Minion struct {
    router *httprouter.Router
}

func New() Minion {
    return Minion{
        router: httprouter.New(),
    }
}

func (m Minion) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    m.router.ServeHTTP(w, r)
}

func (m Minion) Get(path string, handler http.Handler, middleware ...Middleware) {
    middleware = append(middleware, pathParamMiddleware(m.router))
    m.router.Handler("GET", path, middlewareAdapter(handler, middleware...))
}

func (m Minion) Post(path string, handler http.Handler, middleware ...Middleware) {
    middleware = append(middleware, pathParamMiddleware(m.router))
    m.router.Handler("POST", path, middlewareAdapter(handler, middleware...))
}

func (m Minion) Put(path string, handler http.HandlerFunc) {
    m.router.HandlerFunc("PUT", path, handler)
}

func (m Minion) Delete(path string, handler http.HandlerFunc) {
    m.router.HandlerFunc("DELETE", path, handler)
}

