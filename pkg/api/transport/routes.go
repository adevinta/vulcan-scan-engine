/*
Copyright 2021 Adevinta
*/

package transport

import (
	"net/http"

	"github.com/gorilla/mux"
)

// AttachRoutes wire handlers with routes
func AttachRoutes(handlers *Handlers) http.Handler {
	r := mux.NewRouter()
	// Healthcheck
	r.Methods("GET").Path("/v1/healthcheck").Handler(handlers.Healthcheck)

	// Scans
	r.Methods("POST").Path("/v1/scans").Handler(handlers.CreateScan)
	r.Methods("GET").Path("/v1/scans").Handler(handlers.ListScans)
	r.Methods("GET").Path("/v1/scans/").Queries("external_id", "{external_id}").Handler(handlers.GetScanByExternalID)
	r.Methods("GET").Path("/v1/scans/{id}").Handler(handlers.GetScan)
	r.Methods("GET").Path("/v1/scans/{id}/checks").Handler(handlers.GetScanChecks)
	r.Methods("POST").Path("/v1/scans/{id}/abort").Handler(handlers.AbortScan)
	return r
}
