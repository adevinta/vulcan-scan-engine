package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	abortEndpoint = "/abort"
)

// Client specifies the interface for the
// client to interact with Stream service.
type Client interface {
	AbortChecks(ctx context.Context, checks []string) error
}

type client struct {
	URL string
}

// NewClient builds a new stream client.
func NewClient(URL string) Client {
	return &client{URL}
}

type abortChecksReq struct {
	Checks []string `json:"checks"`
}

func (c *client) AbortChecks(ctx context.Context, checks []string) error {
	reqBody, err := json.Marshal(abortChecksReq{checks})
	if err != nil {
		return err
	}
	url := fmt.Sprint(c.URL, abortEndpoint)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	if !isOKStatus(resp.StatusCode) {
		respBody, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		return fmt.Errorf("err: stream returned wrong HTTP status %d with body: %s",
			resp.StatusCode, string(respBody))
	}
	return nil
}

func isOKStatus(s int) bool {
	return 200 >= s && s < 300
}
