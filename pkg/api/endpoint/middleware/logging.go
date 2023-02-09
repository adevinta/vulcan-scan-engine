/*
Copyright 2021 Adevinta
*/

package middleware

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func toStr(obj interface{}) string {
	buf, err := json.Marshal(obj)
	if err != nil {
		return err.Error()
	}
	return string(buf)
}

func Logging(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			begin := time.Now()
			response, err = next(ctx, request)
			_ = level.Debug(logger).Log("Request", toStr(request), "Response", toStr(response), "TransportError", err, "Took", time.Since(begin))
			return response, err
		}
	}
}
