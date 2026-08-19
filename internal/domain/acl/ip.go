package acl

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"go4.org/netipx"
)

var (
	ErrInvalidIPOrPrefix = errors.New("invalid IP address or CIDR string")
)

type IPSet struct {
	set *netipx.IPSet
}

func (ips IPSet) Contains(ip netip.Addr) bool {
	return ips.set.Contains(ip)
}

func (ips IPSet) String() string {
	prefixes := ips.set.Prefixes()

	var sb strings.Builder
	for i, prefix := range prefixes {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(prefix.String())
	}

	return sb.String()
}

func ParseIPSet(s string) (IPSet, error) {
	var ipsb netipx.IPSetBuilder

	for prefix := range strings.SplitSeq(s, ",") {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			addr, err := netip.ParseAddr(prefix)
			if err != nil {
				return IPSet{}, fmt.Errorf("%w: %s", ErrInvalidIPOrPrefix, prefix)
			}
			ipsb.Add(addr)
			continue
		}
		ipsb.AddPrefix(p)
	}

	set, err := ipsb.IPSet()
	if err != nil {
		return IPSet{}, fmt.Errorf("%w: %s", ErrInvalidIPOrPrefix, s)
	}

	return IPSet{
		set: set,
	}, nil
}

func (ips IPSet) MarshalJSON() ([]byte, error) {
	return []byte(`"` + ips.String() + `"`), nil
}

func (ips *IPSet) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	parsed, err := ParseIPSet(s)
	if err != nil {
		return err
	}
	*ips = parsed
	return nil
}
