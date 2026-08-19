package acl

import "net/netip"

type Rule struct {
	action   Action
	protocol Protocol
	ips      IPSet
	ports    PortSet
}

func NewRule(action Action, proto Protocol, ips IPSet, ports PortSet) Rule {
	return Rule{
		action:   action,
		protocol: proto,
		ips:      ips,
		ports:    ports,
	}
}

func (r Rule) Matches(proto Protocol, ip netip.Addr, port uint16) bool {
	if !r.protocol.Contains(proto) {
		return false
	}
	if !r.ports.Contains(port) {
		return false
	}
	if !r.ips.Contains(ip) {
		return false
	}
	return true
}

func (r Rule) Action() Action {
	return r.action
}
