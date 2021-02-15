/*
Copyright 2021 Adevinta
*/

package endpoint

import (
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
)

// ScanEngineService contains the services needed by all the endpoints.
type ScanEngineService interface {
	HealthChecker
	ScanCreator
	ScanGetter
}

// Endpoints contains all available endpoints for this api
type Endpoints struct {
	Healthcheck         endpoint.Endpoint
	CreateScan          endpoint.Endpoint
	GetScan             endpoint.Endpoint
	GetScanByExternalID endpoint.Endpoint
	GetScanChecks       endpoint.Endpoint
	AbortScan           endpoint.Endpoint
}

// MakeEndpoints initialize endpoints using the given service
func MakeEndpoints(s ScanEngineService) *Endpoints {
	return &Endpoints{
		Healthcheck:         makeHealthcheckEndpoint(s),
		CreateScan:          makeCreateScanEndpoint(s),
		GetScan:             makeGetScanEndpoint(s),
		GetScanByExternalID: makeGetScanByExternalIDEndpoint(s),
		GetScanChecks:       makeGetScanChecksEndpoint(s),
		AbortScan:           makeAbortScanEndpoint(s),
	}
}

type HTTPResponse interface {
	StatusCode() int
}

type Created struct {
	Data interface{}
}

func (c Created) StatusCode() int {
	return http.StatusCreated
}

func (c Created) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Data)
}

type Ok struct {
	Data interface{}
}

func (c Ok) StatusCode() int {
	return http.StatusOK
}

func (c Ok) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Data)
}

type Accepted struct {
	Data interface{}
}

func (c Accepted) StatusCode() int {
	return http.StatusAccepted
}

type ServerDown struct {
	Data interface{}
}

func (c ServerDown) StatusCode() int {
	return http.StatusInternalServerError
}

func (c ServerDown) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Data)
}

type NoContent struct {
	Data interface{}
}

func (c NoContent) StatusCode() int {
	return http.StatusNoContent
}

func (c NoContent) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Data)
}
