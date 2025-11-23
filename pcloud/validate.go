package pcloud

import "errors"

type Mode int

const (
	ModeOr  Mode = 0
	ModeAnd Mode = 1
)

func Require(params map[string]any, keys []string, mode Mode) error {
	found := []string{}
	for _, k := range keys {
		if _, ok := params[k]; ok {
			found = append(found, k)
		}
	}
	if mode == ModeOr && len(found) > 0 {
		return nil
	}
	if mode == ModeAnd && len(found) == len(keys) {
		return nil
	}
	return errors.New("required parameter missing: " + join(keys))
}

func join(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	out := ss[0]
	for i := 1; i < len(ss); i++ {
		out += ", " + ss[i]
	}
	return out
}

