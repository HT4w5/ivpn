package access

import (
	"net/netip"

	"github.com/HT4w5/ivpn/internal/domain/acl"
)

func (k *Key) EvaluateACL(proto acl.Protocol, ip netip.Addr, port uint16) acl.Action {
	for _, r := range k.aclRules {
		if r.Matches(proto, ip, port) {
			return r.Action()
		}
	}
	return k.defaultAction
}
