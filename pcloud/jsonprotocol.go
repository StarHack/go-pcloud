package pcloud

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

type JSONConnection struct {
	api     *Client
	session *http.Client
}

func (j *JSONConnection) Connect() Connector { return j }

func (j *JSONConnection) DoGetRequest(method string, authenticate bool, decodeJSON bool, endpoint string, params map[string]any) (any, error) {
	if params == nil {
		params = map[string]any{}
	}
	if authenticate {
		if j.api.AuthToken != "" {
			params["auth"] = j.api.AuthToken
		} else if j.api.AccessToken != "" {
			params["access_token"] = j.api.AccessToken
		}
	}
	if endpoint == "" {
		endpoint = j.api.Endpoint
	}
	q := url.Values{}
	for k, v := range params {
		switch vv := v.(type) {
		case string:
			q.Set(k, vv)
		case int:
			q.Set(k, itoa(vv))
		case int64:
			q.Set(k, itoa64(vv))
		case bool:
			if vv {
				q.Set(k, "1")
			} else {
				q.Set(k, "0")
			}
		default:
			q.Set(k, toString(v))
		}
	}
	u := endpoint + method + "?" + q.Encode()
	getMethod := http.Get
	if _, ok := params["use_session"]; ok {
		getMethod = j.session.Get
	}
	resp, err := getMethod(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if !decodeJSON {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (j *JSONConnection) Upload(method string, files [][2]io.Reader, filenames []string, fields map[string]string) (map[string]any, error) {
	if j.api.AuthToken != "" {
		fields["auth"] = j.api.AuthToken
	} else if j.api.AccessToken != "" {
		fields["access_token"] = j.api.AccessToken
	}
	return j.api.multipartUpload(method, files, filenames, fields)
}

func itoa(i int) string { return toString(i) }
func itoa64(i int64) string {
	return toString(i)
}
func toString(v any) string {
	b, _ := json.Marshal(v)
	return string(bytes.Trim(b, `"`))
}
