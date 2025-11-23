package pcloud

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

type BinaryConnection struct {
	api     *Client
	timeout time.Duration
	conn    net.Conn
	fp      *bufio.ReadWriter
	server  string
}

func (b *BinaryConnection) Connect() Connector {
	u, _ := url.Parse(b.api.Endpoint)
	b.server = u.Host
	b.timeout = 30 * time.Second
	d := &net.Dialer{Timeout: b.timeout}
	// Use Binary Protocol TLS port 8399 as per pCloud documentation.
	c, err := tls.DialWithDialer(d, "tcp", b.server+":8399", &tls.Config{ServerName: b.server})
	if err != nil {
		// Fallback to 443 in case provider has TLS proxying for binary protocol.
		c, _ = tls.DialWithDialer(d, "tcp", b.server+":443", &tls.Config{ServerName: b.server})
	}
	b.conn = c
	b.fp = bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	return b
}

func (b *BinaryConnection) DoGetRequest(method string, authenticate bool, decodeJSON bool, endpoint string, params map[string]any) (any, error) {
	if params == nil {
		params = map[string]any{}
	}
	if authenticate {
		if b.api.AuthToken != "" {
			params["auth"] = b.api.AuthToken
		} else if b.api.AccessToken != "" {
			params["access_token"] = b.api.AccessToken
		}
	}
	if err := b.sendCommandNB(method, params, nil, nil, nil); err != nil {
		return nil, err
	}
	return b.getResult()
}

func (b *BinaryConnection) Upload(method string, files [][2]io.Reader, filenames []string, fields map[string]string) (map[string]any, error) {
	for k, v := range fields {
		if v == "" {
			delete(fields, k)
		}
	}
	if b.api.AuthToken != "" {
		fields["auth"] = b.api.AuthToken
	} else if b.api.AccessToken != "" {
		fields["access_token"] = b.api.AccessToken
	}
	var last map[string]any
	for i, pair := range files {
		name := "data-upload.bin"
		if i < len(filenames) && filenames[i] != "" {
			name = filenames[i]
		}
		ps := map[string]any{}
		for k, v := range fields {
			ps[k] = v
		}
		ps["filename"] = name
		if err := b.sendCommandNB(method, ps, pair[1], nil, nil); err != nil {
			return nil, err
		}
		r, err := b.getResult()
		if err != nil {
			return nil, err
		}
		last = r.(map[string]any)
	}
	return last, nil
}

func (b *BinaryConnection) sendCommandNB(method string, params map[string]any, data io.Reader, dataLen *int64, progress func(int)) error {
	l := int64(-1)
	if data != nil && dataLen == nil {
		type sizer interface{ Size() int64 }
		if se, ok := data.(sizer); ok {
			l = se.Size()
		}
	}
	if data == nil {
		l = -1
	}
	req := b.prepare(method, params, l)
	if err := binary.Write(b.fp, binary.LittleEndian, uint16(len(req))); err != nil {
		return err
	}
	if _, err := b.fp.Write(req); err != nil {
		return err
	}
	if data != nil {
		if l > 0 {
			if _, err := io.CopyN(b.fp, data, l); err != nil {
				return err
			}
		} else {
			if _, err := io.Copy(b.fp, data); err != nil {
				return err
			}
		}
	}
	return b.fp.Flush()
}

func (b *BinaryConnection) prepare(method string, params map[string]any, dataLen int64) []byte {
	var out []byte
	m := []byte(method)
	ml := byte(len(m))
	if dataLen >= 0 {
		ml |= 0x80
	}
	out = append(out, ml)
	if dataLen >= 0 {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(dataLen))
		out = append(out, buf...)
	}
	out = append(out, m...)
	out = append(out, byte(len(params)))
	for k, v := range params {
		key := []byte(k)
		kl := byte(len(key))
		switch t := v.(type) {
		case string:
			out = append(out, kl)
			out = append(out, key...)
			lb := make([]byte, 4)
			binary.LittleEndian.PutUint32(lb, uint32(len(t)))
			out = append(out, lb...)
			out = append(out, []byte(t)...)
		case int:
			out = append(out, kl|0x40)
			out = append(out, key...)
			lb := make([]byte, 8)
			binary.LittleEndian.PutUint64(lb, uint64(t))
			out = append(out, lb...)
		case int64:
			out = append(out, kl|0x40)
			out = append(out, key...)
			lb := make([]byte, 8)
			binary.LittleEndian.PutUint64(lb, uint64(t))
			out = append(out, lb...)
		case bool:
			out = append(out, kl|0x80)
			out = append(out, key...)
			if t {
				out = append(out, 1)
			} else {
				out = append(out, 0)
			}
		default:
			str := toString(v)
			out = append(out, kl)
			out = append(out, key...)
			lb := make([]byte, 4)
			binary.LittleEndian.PutUint32(lb, uint32(len(str)))
			out = append(out, lb...)
			out = append(out, []byte(str)...)
		}
	}
	return out
}

func (b *BinaryConnection) getResult() (any, error) {
	if _, err := b.fp.Peek(1); err != nil {
		return nil, err
	}
	if _, err := b.fp.Discard(4); err != nil {
		return nil, err
	}
	return b.readObject(map[int]string{})
}

func (b *BinaryConnection) readDict(stringsMap map[int]string) (any, error) {
	res := map[string]any{}
	for {
		p, _ := b.fp.Peek(1)
		if len(p) == 0 {
			return nil, errors.New("unexpected eof")
		}
		if p[0] == 255 {
			_, _ = b.fp.ReadByte()
			break
		}
		k, err := b.readObject(stringsMap)
		if err != nil {
			return nil, err
		}
		v, err := b.readObject(stringsMap)
		if err != nil {
			return nil, err
		}
		res[k.(string)] = v
	}
	if dlen, ok := res["data"].(int); ok && dlen > 0 {
		return b.readData(int64(dlen))
	}
	return res, nil
}

func (b *BinaryConnection) readList(stringsMap map[int]string) (any, error) {
	var res []any
	for {
		p, _ := b.fp.Peek(1)
		if p[0] == 255 {
			_, _ = b.fp.ReadByte()
			break
		}
		o, err := b.readObject(stringsMap)
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (b *BinaryConnection) readObject(stringsMap map[int]string) (any, error) {
	t, err := b.fp.ReadByte()
	if err != nil {
		return nil, err
	}
	if (t <= 3) || (100 <= t && t <= 149) {
		var l int
		if 100 <= t {
			l = int(t - 100)
		} else {
			n := int(t) + 1
			buf := make([]byte, n)
			if _, err := io.ReadFull(b.fp, buf); err != nil {
				return nil, err
			}
			l = int(le(buf))
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(b.fp, buf); err != nil {
			return nil, err
		}
		s := string(buf)
		stringsMap[len(stringsMap)] = s
		return s, nil
	} else if 4 <= t && t <= 7 {
		n := int(t - 3)
		buf := make([]byte, n)
		if _, err := io.ReadFull(b.fp, buf); err != nil {
			return nil, err
		}
		idx := int(le(buf))
		return stringsMap[idx], nil
	} else if 8 <= t && t <= 15 {
		n := int(t - 7)
		buf := make([]byte, n)
		if _, err := io.ReadFull(b.fp, buf); err != nil {
			return nil, err
		}
		return int(le(buf)), nil
	} else if t == 16 {
		return b.readDict(stringsMap)
	} else if t == 17 {
		return b.readList(stringsMap)
	} else if t == 18 {
		return false, nil
	} else if t == 19 {
		return true, nil
	} else if t == 20 {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(b.fp, buf); err != nil {
			return nil, err
		}
		return int(le(buf)), nil
	} else if 150 <= t && t <= 199 {
		return stringsMap[int(t-150)], nil
	} else if 200 <= t && t <= 219 {
		return int(t - 200), nil
	}
	return nil, errors.New("unknown value")
}

func (b *BinaryConnection) readData(n int64) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(b.fp, buf)
	return buf, err
}

func le(b []byte) uint64 {
	var x uint64
	for i := len(b) - 1; i >= 0; i-- {
		x = (x << 8) | uint64(b[i])
	}
	return x
}

func (b *BinaryConnection) Close() error {
	if b.conn != nil {
		return b.conn.Close()
	}
	return nil
}

func (b *BinaryConnection) UploadNotSupportedNotice() error {
	return errors.New("not supported")
}

func isBoolString(s string) bool {
	return s == "0" || s == "1" || strings.EqualFold(s, "true") || strings.EqualFold(s, "false")
}
