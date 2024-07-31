package veloce

import (
	"net/http"
)


type Router struct {
	Mux *http.ServeMux
}


func NewRouter() *Router{
	mux := http.NewServeMux()
	return &Router{
		Mux: mux,
	}
}


func (r *Router) Handle(method string,path string, handler http.HandlerFunc) {
	r.Mux.HandleFunc(path, http_method_guard(method, handler))
}