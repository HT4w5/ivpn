package acl

import (
	"errors"
	"fmt"
	"strings"
)

// Protocol represents a list of transport layer protocols.
// Current supported protocols are: TCP, UDP.
type Protocol uint8

const (
	ProtocolNone Protocol = 0
	ProtocolTCP  Protocol = 1 << iota
	ProtocolUDP

	ProtocolAny = 0xFF
)

var (
	ErrInvalidProtocol = errors.New("invalid protocol string")
)

// Matches reports if p overlaps with flag.
func (p Protocol) Overlaps(flag Protocol) bool {
	return (p & flag) != 0
}

// Has reports if p contains flag.
func (p Protocol) Contains(flag Protocol) bool {
	return (p & flag) == flag
}

func (p Protocol) String() string {
	switch p {
	case ProtocolNone:
		return "none"
	case ProtocolAny:
		return "any"
	}

	var protos []string
	if p.Contains(ProtocolTCP) {
		protos = append(protos, "tcp")
	}
	if p.Contains(ProtocolUDP) {
		protos = append(protos, "udp")
	}

	if len(protos) == 0 {
		return "none"
	}

	return strings.Join(protos, ",")
}

func ParseProtocol(s string) (Protocol, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ProtocolNone, nil
	}
	if s == "*" || s == "any" {
		return ProtocolAny, nil
	}

	var mask Protocol
	tokens := strings.Split(s, ",")

	for _, token := range tokens {
		switch token {
		case "tcp":
			mask |= ProtocolTCP
		case "udp":
			mask |= ProtocolUDP
		default:
			return ProtocolNone, fmt.Errorf("%w: %s", ErrInvalidProtocol, token)
		}
	}

	return mask, nil
}

func (p Protocol) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}

func (p *Protocol) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	parsed, err := ParseProtocol(s)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}
