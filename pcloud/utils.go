package pcloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

func ToAPIDatetime(t time.Time) string {
	return t.Format(time.RFC3339)
}

func jsonUnmarshalNumbers(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(v)
}

func jsonMarshalNoEscape(v any) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func (t *RFC1123Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil || s == "" {
		*t = RFC1123Time{}
		return err
	}
	x, err := time.Parse(time.RFC1123Z, s)
	if err != nil {
		return err
	}
	*t = RFC1123Time{x}
	return nil
}

// NumericString accepts either a JSON number (including scientific notation) or a string,
// and stores the original token as a string without precision loss.
type NumericString string

func (n *NumericString) UnmarshalJSON(b []byte) error {
	sb := strings.TrimSpace(string(b))
	if sb == "" || sb == "null" {
		*n = ""
		return nil
	}
	// if it's already a quoted string, keep it as-is
	if sb[0] == '"' && sb[len(sb)-1] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*n = NumericString(s)
		return nil
	}
	// otherwise treat as number token and preserve its literal form
	var num json.Number
	if err := json.Unmarshal(b, &num); err != nil {
		return err
	}
	*n = NumericString(num.String())
	return nil
}

func (n *Int64Number) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		*n = 0
		return nil
	}
	if b[0] == '"' && b[len(b)-1] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if s == "" {
			*n = 0
			return nil
		}
		if strings.ContainsAny(s, "eE.") {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return err
			}
			*n = Int64Number(int64(math.Round(f)))
			return nil
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			f, err2 := strconv.ParseFloat(s, 64)
			if err2 != nil {
				return err
			}
			*n = Int64Number(int64(math.Round(f)))
			return nil
		}
		*n = Int64Number(i)
		return nil
	}
	var num json.Number
	if err := json.Unmarshal(b, &num); err != nil {
		return err
	}
	if i, err := num.Int64(); err == nil {
		*n = Int64Number(i)
		return nil
	}
	f, err := strconv.ParseFloat(num.String(), 64)
	if err != nil {
		return err
	}
	*n = Int64Number(int64(math.Round(f)))
	return nil
}

func apiErr(result int, msg string) error {
	switch result {
	case 0:
		return nil
	case 2004:
		return ErrFolderAlreadyExists
	case 2001:
		return ErrFileNotFound
	case 1000:
		return ErrInvalidAuth
	default:
		if msg == "" {
			msg = "unknown error"
		}
		return errors.New(msg)
	}
}
