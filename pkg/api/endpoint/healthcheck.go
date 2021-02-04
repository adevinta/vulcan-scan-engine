/*
Copyright 2021 Adevinta
*/

package endpoint

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

type HealthcheckResponse struct {
	Status string `json:"status"`
}

// HealthChecker defines the services needed by the endpoint.
type HealthChecker interface {
	Healthcheck(context.Context) error
}

func makeHealthcheckEndpoint(svc HealthChecker) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		resp := HealthcheckResponse{}
		err = svc.Healthcheck(ctx)
		if err != nil {
			resp.Status = "KO"
			return ServerDown{resp}, nil
		}
		resp.Status = "OK"
		return Ok{resp}, nil
	}
}
