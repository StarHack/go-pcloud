package pcloud

type TestProtocolDef struct {
	Name      string
	Endpoint  string
	Connection func(*Client) Connector
}

var (
	TestProtocolSpec = TestProtocolDef{Name: "test", Endpoint: "http://localhost:5023/", Connection: func(c *Client) Connector { return &JSONConnection{api: c} }}
	JsonAPISpec      = TestProtocolDef{Name: "api", Endpoint: "https://api.pcloud.com/", Connection: func(c *Client) Connector { return &JSONConnection{api: c} }}
	JsonEAPISpec     = TestProtocolDef{Name: "eapi", Endpoint: "https://eapi.pcloud.com/", Connection: func(c *Client) Connector { return &JSONConnection{api: c} }}
	BinAPISpec       = TestProtocolDef{Name: "binapi", Endpoint: "https://binapi.pcloud.com/", Connection: func(c *Client) Connector { return &BinaryConnection{api: c} }}
	BinEAPISpec      = TestProtocolDef{Name: "bineapi", Endpoint: "https://bineapi.pcloud.com/", Connection: func(c *Client) Connector { return &BinaryConnection{api: c} }}
	NearestSpec      = TestProtocolDef{Name: "nearest", Endpoint: "", Connection: func(c *Client) Connector { return &JSONConnection{api: c} }}
)

