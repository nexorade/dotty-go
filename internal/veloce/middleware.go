package veloce

import "net/http"



func http_method_guard (method string,next http.HandlerFunc) http.HandlerFunc{
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == method {
			next(w,r)
		}else{
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed."))
		}
	})
}

