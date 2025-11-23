package pcloud

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrAuthentication = errors.New("authentication failed")
	ErrOnlyPcloud     = errors.New("this method can't be used from web applications. referrer is restricted to pcloud.com.")
)

type EndpointKey string

const (
	EndpointAPI     EndpointKey = "api"
	EndpointEAPI    EndpointKey = "eapi"
	EndpointTest    EndpointKey = "test"
	EndpointBinAPI  EndpointKey = "binapi"
	EndpointBinEAPI EndpointKey = "bineapi"
	EndpointNearest EndpointKey = "nearest"
)

type Client struct {
	Endpoint       string
	Username       string
	Password       string
	CryptoPassword string
	TokenExpire    int
	AccessToken    string
	AuthToken      string
	http           *http.Client
	jsonConn       *JSONConnection
	oauth2         bool
	endpointKeys   map[EndpointKey]Protocol
	// Crypto fields - populated when CryptoPassword is set
	privateKey string   // Encoded private key from API
	publicKey  string   // Encoded public key from API
	keyPair    *KeyPair // Decrypted key pair
	KeyPair    *KeyPair
}

type Protocol struct {
	Name      string
	Endpoint  string
	Connector func(*Client) Connector
}

type Connector interface {
	Connect() Connector
	DoGetRequest(method string, authenticate bool, decodeJSON bool, endpoint string, params map[string]any) (any, error)
	Upload(method string, files [][2]io.Reader, filenames []string, fields map[string]string) (map[string]any, error)
}

func NewClient(username, password, cryptopassword string, endpoint EndpointKey) (*Client, error) {
	eps := map[EndpointKey]Protocol{
		EndpointAPI: {Name: "api", Endpoint: "https://api.pcloud.com/", Connector: func(c *Client) Connector {
			return &JSONConnection{api: c, session: &http.Client{Timeout: 30 * time.Second}}
		}},
		EndpointEAPI: {Name: "eapi", Endpoint: "https://eapi.pcloud.com/", Connector: func(c *Client) Connector {
			return &JSONConnection{api: c, session: &http.Client{Timeout: 30 * time.Second}}
		}},
		EndpointTest: {Name: "test", Endpoint: "http://localhost:5023/", Connector: func(c *Client) Connector {
			return &JSONConnection{api: c, session: &http.Client{Timeout: 30 * time.Second}}
		}},
		EndpointBinAPI:  {Name: "binapi", Endpoint: "https://binapi.pcloud.com/", Connector: func(c *Client) Connector { return &BinaryConnection{api: c} }},
		EndpointBinEAPI: {Name: "bineapi", Endpoint: "https://bineapi.pcloud.com/", Connector: func(c *Client) Connector { return &BinaryConnection{api: c} }},
		EndpointNearest: {Name: "nearest", Endpoint: "", Connector: func(c *Client) Connector {
			return &JSONConnection{api: c, session: &http.Client{Timeout: 30 * time.Second}}
		}},
	}
	if _, ok := eps[endpoint]; !ok {
		return nil, fmt.Errorf("unknown endpoint %q", endpoint)
	}
	c := &Client{
		http:           &http.Client{Timeout: 30 * time.Second},
		TokenExpire:    31536000, // 1 year
		Username:       strings.ToLower(username),
		Password:       password,
		CryptoPassword: cryptopassword,
		oauth2:         false, // not properly tested
		endpointKeys:   eps,
	}
	if endpoint == EndpointNearest {
		u, err := c.getNearestEndpoint()
		if err != nil {
			return nil, err
		}
		c.Endpoint = u
		c.jsonConn = eps[EndpointNearest].Connector(c).Connect().(*JSONConnection)
	} else {
		proto := eps[endpoint]
		c.Endpoint = proto.Endpoint
		c.jsonConn = proto.Connector(c).Connect().(*JSONConnection)
	}
	if c.oauth2 {
		c.AccessToken = password
		c.AuthToken = ""
		return c, nil
	}
	if username == "" && password == "" {
		return c, nil
	}
	auth, err := c.getAuthToken()
	if err != nil {
		return nil, err
	}
	c.AuthToken = auth

	// If CryptoPassword is set, retrieve and decrypt the user keys
	if c.CryptoPassword != "" {
		privateKey, publicKey, err := c.getCryptoUserKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to get crypto user keys: %w", err)
		}
		c.privateKey = privateKey
		c.publicKey = publicKey

		// Decrypt the private key using the crypto password
		keyPair, err := DecryptPrivateKey(c.CryptoPassword, privateKey, publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
		c.keyPair = keyPair
		c.KeyPair = keyPair
	}

	return c, nil
}

func (c *Client) oauth2Authorize(clientID, clientSecret string, tokenExpire int) (*Client, error) {
	m := map[string]EndpointKey{}
	for k, p := range c.endpointKeys {
		u, _ := url.Parse(p.Endpoint)
		m[u.Host] = k
	}
	code, hostname, err := DefaultTokenHandler(clientID).GetAccessToken()
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("client_secret", clientSecret)
	params.Set("code", code)
	endKey := m[hostname]
	endURL := c.endpointKeys[endKey].Endpoint
	resp, err := c.http.Get(endURL + "oauth2_token?" + params.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	accessToken, _ := out["access_token"].(string)
	return NewClient("", accessToken, "", endKey /*, c.TokenExpire, true*/)
}

func (c *Client) call(method string, authenticate bool, decodeJSON bool, endpoint string, params map[string]any) (any, error) {
	return c.jsonConn.DoGetRequest(method, authenticate, decodeJSON, endpoint, params)
}

func (c *Client) getDigest() ([]byte, error) {
	r, err := c.call("getdigest", false, true, "", nil)
	if err != nil {
		return nil, err
	}
	m := r.(map[string]any)
	d, _ := m["digest"].(string)
	return []byte(d), nil
}

func (c *Client) getAuthToken() (string, error) {
	d, err := c.getDigest()
	if err != nil {
		return "", err
	}
	h1 := sha1.Sum([]byte(c.Username))
	concat := append([]byte(c.Password), []byte(hex.EncodeToString(h1[:]))...)
	concat = append(concat, d...)
	h := sha1.Sum(concat)
	params := map[string]any{
		"getauth":        1,
		"logout":         1,
		"username":       c.Username,
		"digest":         string(d),
		"passworddigest": hex.EncodeToString(h[:]),
		"authexpire":     c.TokenExpire,
	}
	r, err := c.call("userinfo", false, true, "", params)
	if err != nil {
		return "", err
	}
	m := r.(map[string]any)
	if a, ok := m["auth"].(string); ok && a != "" {
		return a, nil
	}
	return "", ErrAuthentication
}

// getCryptoUserKeys retrieves the user's encrypted private and public keys from the API.
// Returns privatekey and publickey strings from the response.
func (c *Client) getCryptoUserKeys() (string, string, error) {
	r, err := c.call("crypto_getuserkeys", true, true, "", nil)
	if err != nil {
		return "", "", err
	}
	m := r.(map[string]any)

	// Check for result code
	if result, ok := m["result"].(float64); ok && result != 0 {
		errMsg, _ := m["error"].(string)
		if errMsg == "" {
			errMsg = fmt.Sprintf("crypto_getuserkeys failed with code %d", int(result))
		}
		return "", "", errors.New(errMsg)
	}

	privateKey, _ := m["privatekey"].(string)
	publicKey, _ := m["publickey"].(string)

	if privateKey == "" || publicKey == "" {
		return "", "", errors.New("missing privatekey or publickey in response")
	}

	return privateKey, publicKey, nil
}

func (c *Client) getNearestEndpoint() (string, error) {
	defaultAPI := c.endpointKeys[EndpointAPI].Endpoint
	r, err := c.call("getapiserver", false, true, defaultAPI, nil)
	if err != nil {
		return "", err
	}
	m := r.(map[string]any)
	apiVal, ok := m["api"]
	if !ok {
		return defaultAPI, nil
	}
	a, ok := apiVal.([]any)
	if !ok || len(a) == 0 {
		return defaultAPI, nil
	}
	host, _ := a[0].(string)
	return (&url.URL{Scheme: "https", Host: host, Path: "/"}).String(), nil
}

func (c *Client) UserInfo() (map[string]any, error) {
	r, err := c.call("userinfo", true, true, "", nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *Client) SupportedLanguages() (map[string]any, error) {
	r, err := c.call("supportedlanguages", true, true, "", nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *Client) SetLanguage(language string) (map[string]any, error) {
	params := map[string]any{"language": language}
	r, err := c.call("setlanguage", true, true, "", params)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *Client) Feedback(mail, reason, message string) (map[string]any, error) {
	params := map[string]any{"mail": mail, "reason": reason, "message": message}
	r, err := c.call("feedback", true, true, "", params)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *Client) CurrentServer() (map[string]any, error) {
	r, err := c.call("currentserver", true, true, "", nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *Client) StatByPath(path string) (map[string]any, error) {
	r, err := c.call("stat", true, true, "", map[string]any{"path": path})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *Client) StatByFileID(fileid int64) (map[string]any, error) {
	r, err := c.call("stat", true, true, "", map[string]any{"fileid": fileid})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *Client) FileExists(path string) (bool, error) {
	resp, err := c.StatByPath(path)
	if err != nil {
		return false, err
	}
	res := intFrom(resp["result"])
	if res == 0 {
		return true, nil
	}
	if res == 2001 || res == 2055 {
		return false, nil
	}
	return false, fmt.Errorf("pcloud error (%d) - %v: %s", res, resp["error"], path)
}

func (c *Client) GetZip(fileids []int64, useSession bool) ([]byte, error) {
	params := map[string]any{"fileids": joinInt64(fileids)}
	if useSession {
		params["use_session"] = 1
	}
	r, err := c.call("getzip", true, false, "", params)
	if err != nil {
		return nil, err
	}
	return r.([]byte), nil
}

func (c *Client) DownloadFile(fileid int64, targetFilePath string) error {
	rc, err := c.DownloadFileStream(fileid)
	if err != nil {
		return err
	}
	defer rc.Close()

	f, err := os.Create(targetFilePath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, rc)
	return err
}

// UploadFile uploads a local file to the specified folder, encrypting if the folder is encrypted.
func (c *Client) UploadFile(folderID int64, localPath string) (*Metadata, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	name := filepath.Base(localPath)
	w, err := c.UploadFileStream(folderID, name)
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(w, f)
	if err != nil {
		_ = w.Close()
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	meta := w.(interface{ Metadata() *Metadata }).Metadata()
	return meta, nil
}

func (c *Client) GetFolderPubLink(path string, folderid int64, expire time.Time) (map[string]any, error) {
	params := map[string]any{}
	if path != "" {
		params["path"] = path
	}
	if folderid != 0 {
		params["folderid"] = folderid
	}
	if !expire.IsZero() {
		params["expire"] = ToAPIDatetime(expire)
	}
	r, err := c.call("getfolderpublink", true, true, "", params)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *Client) GetPubZip(code string, unzip bool) ([]byte, error) {
	params := map[string]any{"code": code}
	r, err := c.call("getpubzip", false, false, "", params)
	if err != nil {
		return nil, err
	}
	b := r.([]byte)
	if !unzip {
		return b, nil
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return []byte{}, nil
	}
	if len(zr.File) == 0 {
		return []byte{}, nil
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (c *Client) OnlyPcloud() error { return ErrOnlyPcloud }

func (c *Client) multipartUpload(method string, files [][2]io.Reader, filenames []string, fields map[string]string) (map[string]any, error) {
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)

	if c.AuthToken != "" {
		fields["auth"] = c.AuthToken
	}
	if c.AccessToken != "" && c.oauth2 {
		fields["access_token"] = c.AccessToken
	}
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return nil, err
		}
	}

	for i, pair := range files {
		fn := "data-upload.bin"
		if i < len(filenames) {
			fn = filenames[i]
		}
		fw, err := w.CreateFormFile("file", fn)
		if err != nil {
			return nil, err
		}
		if pair[1] != nil {
			if _, err := io.Copy(fw, pair[1]); err != nil {
				return nil, err
			}
		}
	}
	_ = w.Close()

	req, err := http.NewRequest(http.MethodPost, c.Endpoint+method, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func joinInt64(v []int64) string {
	if len(v) == 0 {
		return ""
	}
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(s, ",")
}

func intFrom(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	default:
		return 0
	}
}
