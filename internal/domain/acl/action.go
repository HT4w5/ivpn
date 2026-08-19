package acl

import (
	"errors"
	"fmt"
	"strings"
)

type Action uint8

const (
	ActionUnknown Action = iota
	ActionAccept
	ActionReject
)

var (
	ErrInvalidAction = errors.New("invalid action string")
)

func (a Action) IsValid() bool {
	switch a {
	case ActionAccept, ActionReject:
		return true
	default:
		return false
	}
}

func (a Action) String() string {
	switch a {
	case ActionAccept:
		return "accept"
	case ActionReject:
		return "reject"
	default:
		return "unknown"
	}
}

func ParseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "accept":
		return ActionAccept, nil
	case "reject":
		return ActionReject, nil
	default:
		return ActionUnknown, fmt.Errorf("%w: %s", ErrInvalidAction, s)
	}
}

func (a Action) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.String() + `"`), nil
}

func (a *Action) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	parsed, err := ParseAction(s)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}
