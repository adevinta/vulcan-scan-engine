/*
Copyright 2021 Adevinta
*/

package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"

	"github.com/adevinta/errors"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

const (
	tagName         = "urlvar"
	headerTagName   = "headervar"
	urlQueryTagname = "urlquery"
)

func makeDecodeRequestFunc(req interface{}) kithttp.DecodeRequestFunc {
	return func(_ context.Context, r *http.Request) (interface{}, error) {
		return setRequestStructFields(req, r)
	}
}

// setRequestStructFields will take a transport layer request struct and set
// the fields using parameters taken from the request route path. For example:
//
// Given the request struct for finding teams by a user_id
//
//	type FindTeamsByUserJSONRequest struct {
//		 UserID string `json:"user_id" urlvar:"user_id"`
//	}
//
// The UserID will be loaded from the request route, in this case:
// /v1/users/{user_id}/teams
//
// The link between the request struct and the route path is a custom tag on the
// struct field, indicating which path paremeter corresponds to this field.
func setRequestStructFields(req interface{}, r *http.Request) (interface{}, error) {
	requestType := reflect.TypeOf(req)
	requestObject := reflect.New(requestType).Interface()

	if r.ContentLength > 0 {
		if !strings.HasPrefix(r.Header.Get("Content-type"), "multipart/form-data") {
			if e := json.NewDecoder(r.Body).Decode(requestObject); e != nil {
				return nil, errors.Assertion("cannot unmarshal " + requestType.Name())
			}
		}
	}

	requestObject = loadParametersFromRequestPath(requestObject, mux.Vars(r))
	requestObject = loadParametersFromRequestHeaders(requestObject, r.Header)
	requestObject = loadParametersFromURLQuery(requestObject, r.URL.Query())
	return requestObject, nil
}

func loadParametersFromURLQuery(requestObject interface{}, vars map[string][]string) interface{} {
	obj := reflect.TypeOf(requestObject).Elem()
	for i := 0; i < obj.NumField(); i++ {
		tag := obj.Field(i).Tag.Get(urlQueryTagname)
		// Skip if tag is not defined or ignored
		if tag == "" || tag == "-" {
			continue
		}
		values := vars[tag]
		if len(values) < 1 {
			continue
		}
		reflect.ValueOf(requestObject).Elem().Field(i).SetString(values[0])
	}

	return requestObject
}

func loadParametersFromRequestPath(requestObject interface{}, vars map[string]string) interface{} {
	obj := reflect.TypeOf(requestObject).Elem()
	for i := 0; i < obj.NumField(); i++ {
		tag := obj.Field(i).Tag.Get(tagName)
		// Skip if tag is not defined or ignored
		if tag == "" || tag == "-" {
			continue
		}

		reflect.ValueOf(requestObject).Elem().Field(i).SetString(vars[tag])
	}

	return requestObject
}

func loadParametersFromRequestHeaders(requestObject interface{}, headers http.Header) interface{} {
	obj := reflect.TypeOf(requestObject).Elem()

	for i := 0; i < obj.NumField(); i++ {
		tag := obj.Field(i).Tag.Get(headerTagName)

		// Skip if tag is not defined or ignored
		if tag == "" || tag == "-" {
			continue
		}

		if len(headers[tag]) > 0 {
			reflect.ValueOf(requestObject).Elem().Field(i).SetString(headers[tag][0])
		}
	}

	return requestObject
}
