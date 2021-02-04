/*
Copyright 2021 Adevinta
*/

package transport

import (
	"net/http"

	kitendpoint "github.com/go-kit/kit/endpoint"
	kitlog "github.com/go-kit/kit/log"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/goadesign/goa/uuid"

	"github.com/adevinta/vulcan-scan-engine/pkg/api/endpoint"

	"context"
)

// CustomCtxKey represents a custom
// key type for API requests context.
type CustomCtxKey int

const (
	// ContextKeyEndpoint is the context key
	// for the requested API endpoint.
	ContextKeyEndpoint CustomCtxKey = iota
)

// Handlers contains all available handlers for this api
type Handlers struct {
	Healthcheck         http.Handler
	CreateScan          http.Handler
	GetScan             http.Handler
	AbortScan           http.Handler
	GetScanByExternalID http.Handler
}

// MakeHandlers returns initialized handlers
func MakeHandlers(e *endpoint.Endpoints, logger kitlog.Logger) *Handlers {
	options := func(endpoint string) []kithttp.ServerOption {
		return []kithttp.ServerOption{
			kithttp.ServerBefore(
				HTTPGenerateXRequestID(),
				kithttp.PopulateRequestContext,
				HTTPRequestLogger(logger, "/v1/healthcheck"),
				HTTPRequestEndpoint(endpoint),
			),
			kithttp.ServerAfter(
				HTTPReturnXRequestID(),
			),
			kithttp.ServerErrorEncoder(
				func(ctx context.Context, err error, w http.ResponseWriter) {
					w.Header().Set("X-Request-ID", ctx.Value(kithttp.ContextKeyRequestXRequestID).(string))
					kithttp.DefaultErrorEncoder(ctx, err, w)
				},
			),
		}
	}

	newServer := func(e kitendpoint.Endpoint,
		decodeRequestFunc kithttp.DecodeRequestFunc, endpoint string) http.Handler {
		return kithttp.NewServer(
			e,
			decodeRequestFunc,
			kithttp.EncodeJSONResponse,
			options(endpoint)...,
		)
	}

	return &Handlers{
		Healthcheck:         newServer(e.Healthcheck, makeDecodeRequestFunc(struct{}{}), "Healthcheck"),
		CreateScan:          newServer(e.CreateScan, makeDecodeRequestFunc(endpoint.ScanRequest{}), "CreateScan"),
		GetScan:             newServer(e.GetScan, makeDecodeRequestFunc(endpoint.ScanRequest{}), "GetScan"),
		AbortScan:           newServer(e.AbortScan, makeDecodeRequestFunc(endpoint.ScanRequest{}), "AbortScan"),
		GetScanByExternalID: newServer(e.GetScanByExternalID, makeDecodeRequestFunc(endpoint.ScanRequest{}), "GetScanByExternalID"),
	}
}

// HTTPGenerateXRequestID gets or create a request id token.
func HTTPGenerateXRequestID() kithttp.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		if r.Header.Get("X-Request-ID") == "" {
			XRequestID := uuid.NewV4()
			r.Header.Set("X-Request-ID", XRequestID.String())
		}
		return ctx
	}
}

func HTTPReturnXRequestID() kithttp.ServerResponseFunc {
	return func(ctx context.Context, w http.ResponseWriter) context.Context {
		w.Header().Set("X-Request-ID", ctx.Value(kithttp.ContextKeyRequestXRequestID).(string))
		return ctx
	}
}

func HTTPRequestLogger(logger kitlog.Logger, exclude string) kithttp.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		path := ctx.Value(kithttp.ContextKeyRequestPath).(string)
		if path != exclude {
			_ = logger.Log(
				"X-Request-ID", ctx.Value(kithttp.ContextKeyRequestXRequestID).(string),
				"transport", ctx.Value(kithttp.ContextKeyRequestPath).(string),
				"Method", ctx.Value(kithttp.ContextKeyRequestMethod).(string),
				"RequestURI", ctx.Value(kithttp.ContextKeyRequestURI).(string))
		}
		return ctx
	}
}

// HTTPRequestEndpoint includes a new request ctx entry
// indicating which endpoint was requested.
func HTTPRequestEndpoint(endpoint string) kithttp.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		return context.WithValue(ctx, ContextKeyEndpoint, endpoint)
	}
}
