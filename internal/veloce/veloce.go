/*
	Required features:
	- Handle HTTP request methods with ease (something similar to express js)
	- Use the native net/http module and alter the interface to support the new methods. Just extend the native module and not replace it.
	- Do not worry too much about serving static files, just support JSON, string
	- Support for path parameters, query parameters, headers, cookies, and body.
	- Support for middlewares
	- Support for route grouping
	- Passing context across the chain of functions
*/

package veloce

import (
	"net/http"
)

type App struct {
	router *http.ServeMux
}


func New() App {
	router := http.NewServeMux()
	return App{router: router}
}



func (a *App) Handle (method string,path string, handler http.HandlerFunc) {
	a.router.HandleFunc(path, http_method_guard(method, handler))
}


func (a *App) Route(prefix string ,router Router){
	if string(prefix[len(prefix) - 1 :]) != "/" {
		prefix = prefix + "/"
	}
	a.router.Handle(prefix, http.StripPrefix(prefix[0:len(prefix) - 1], router.Mux))
}


func (a *App) Serve (address string) error {
	return http.ListenAndServe(address, a.router)
}