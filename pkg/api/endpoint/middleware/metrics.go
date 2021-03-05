/*
Copyright 2021 Adevinta
*/

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/adevinta/errors"
	metrics "github.com/adevinta/vulcan-metrics-client"
	kitendpoint "github.com/go-kit/kit/endpoint"
	kithttp "github.com/go-kit/kit/transport/http"

	"github.com/adevinta/vulcan-scan-engine/pkg/api/endpoint"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/transport"
)

const (
	// Metric names
	metricTotal    = "vulcan.request.total"
	metricDuration = "vulcan.request.duration"
	metricFailed   = "vulcan.request.failed"

	// Tags
	tagComponent = "component"
	tagAction    = "action"
	tagEntity    = "entity"
	tagMethod    = "method"
	tagStatus    = "status"

	// Entities
	entityScan = "scan"

	scanengineComponent = "scanengine"
)

// MetricsMiddleware implements a metrics middleware over an endpoint.
type MetricsMiddleware interface {
	Measure() kitendpoint.Middleware
}

type metricsMiddleware struct {
	metricsClient metrics.Client
}

// NewMetricsMiddleware creates a new metrics middleware pushing the
// metrics through the given metrics client.
func NewMetricsMiddleware(metricsClient metrics.Client) MetricsMiddleware {
	return &metricsMiddleware{
		metricsClient: metricsClient,
	}
}

func (m *metricsMiddleware) Measure() kitendpoint.Middleware {
	return func(next kitendpoint.Endpoint) kitendpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			// Time and execute request
			reqStart := time.Now()
			res, err := next(ctx, request)
			reqEnd := time.Now()

			// Collect metrics
			endpoint := ctx.Value(transport.ContextKeyEndpoint).(string)
			httpMethod := ctx.Value(kithttp.ContextKeyRequestMethod).(string)
			httpStatus := parseHTTPStatus(res, err)
			duration := reqEnd.Sub(reqStart).Milliseconds()
			failed := httpStatus >= 400

			// Build tags
			tags := []string{
				fmt.Sprint(tagComponent, ":", scanengineComponent),
				fmt.Sprint(tagAction, ":", endpoint),
				fmt.Sprint(tagEntity, ":", entityScan),
				fmt.Sprint(tagMethod, ":", httpMethod),
				fmt.Sprint(tagStatus, ":", httpStatus),
			}

			// Push metrics
			m.pushMetrics(httpMethod, duration, failed, tags)

			return res, err
		}
	}
}

func (m *metricsMiddleware) pushMetrics(httpMethod string, duration int64, failed bool, tags []string) {
	mm := []metrics.Metric{
		{
			Name:  metricTotal,
			Typ:   metrics.Count,
			Value: 1,
			Tags:  tags,
		},
		{
			Name:  metricDuration,
			Typ:   metrics.Histogram,
			Value: float64(duration),
			Tags:  tags,
		},
	}
	if failed {
		mm = append(mm, metrics.Metric{
			Name:  metricFailed,
			Typ:   metrics.Count,
			Value: 1,
			Tags:  tags,
		})
	}

	for _, met := range mm {
		m.metricsClient.Push(met)
	}
}

func parseHTTPStatus(resp interface{}, err error) int {
	// If err is not nil, try to cast to ErrStack and
	// return its StatusCode.
	// Otherwise default to HTTP 500 status code.
	if err != nil {
		if errStack, ok := err.(*errors.ErrorStack); ok {
			return errStack.StatusCode()
		}
		return http.StatusInternalServerError
	}

	// If err is nil, try to cast to endpoint HTTPResponse
	// and return its StatusCode.
	// Otherwise default to HTTP 200 status code.
	if httpResp, ok := resp.(endpoint.HTTPResponse); ok {
		return httpResp.StatusCode()
	}
	return http.StatusOK
}
