/*
Copyright 2021 Adevinta
*/

package transport

import (
	"context"
	//"log"
	"net/http"

	kithttp "github.com/go-kit/kit/transport/http"
)

// TODO: this is a temporary logger. It will be replaced later when we have a
// stable version
func HttpRequestLogger() kithttp.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		//log.Printf("http.Request: %+v", r)
		return ctx
	}
}
