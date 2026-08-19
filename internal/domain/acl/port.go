package acl

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

var (
	ErrInvalidPortRange = errors.New("invalid port range string")
)

// PortRange Represents a continuous range of uint16 ports.
// It contains at least one port.
type PortRange struct {
	// (min, max]
	min uint16
	max uint16
}

// NewPortRange returns a PortRange of [min, max].
// Behavior is undefined if min=0 or min>max.
func NewPortRange(min, max uint16) PortRange {
	return PortRange{
		min: min - 1,
		max: max,
	}
}

// Contains reports if port is in pr.
func (pr PortRange) Contains(port uint16) bool {
	return pr.min < port && port <= pr.max
}

func (pr PortRange) String() string {
	if pr.min+1 == pr.max {
		return strconv.FormatUint(uint64(pr.max), 10)
	}
	if pr.min == 0 && pr.max == math.MaxUint16 {
		return "any"
	}

	return strconv.FormatUint(uint64(pr.min+1), 10) +
		"-" +
		strconv.FormatUint(uint64(pr.max), 10)
}

func ParsePortRange(s string) (PortRange, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "*" || s == "any" {
		return PortRange{
			min: 0,
			max: math.MaxUint16,
		}, nil
	}
	dashIdx := strings.IndexByte(s, '-')
	if dashIdx < 0 {
		if port, err := strconv.ParseUint(s, 10, 16); err != nil || port == 0 {
			return PortRange{}, fmt.Errorf("%w: %s", ErrInvalidPortRange, s)
		} else {
			return PortRange{
				min: uint16(port - 1),
				max: uint16(port),
			}, nil
		}
	}

	min, err := strconv.ParseUint(s[:dashIdx], 10, 16)
	if err != nil {
		return PortRange{}, fmt.Errorf("%w: %s", ErrInvalidPortRange, s)
	}
	max, err := strconv.ParseUint(s[dashIdx+1:], 10, 16)
	if err != nil {
		return PortRange{}, fmt.Errorf("%w: %s", ErrInvalidPortRange, s)
	}

	if min == 0 || min > max {
		return PortRange{}, fmt.Errorf("%w: %s", ErrInvalidPortRange, s)
	}

	return PortRange{
		min: uint16(min - 1),
		max: uint16(max),
	}, nil
}

// PortSet represents
type PortSet struct {
	pr []PortRange
}

// NewPortSet returns a PortSet from ranges.
func NewPortSet(ranges []PortRange) PortSet {
	pr := make([]PortRange, 0, len(ranges))
	for _, r := range ranges {
		pr = append(pr, r)
	}
	set := PortSet{
		pr: pr,
	}
	set.optimize()
	return set
}

// Contains reports if port is in ps.
func (ps PortSet) Contains(port uint16) bool {
	for _, pr := range ps.pr {
		if pr.Contains(port) {
			return true
		}
	}
	return false
}

// optimize tries to merge PortRanges in ps.
// If ps is already sorted and non-overlapping, this is O(n).
func (ps *PortSet) optimize() {
	if len(ps.pr) <= 1 {
		return
	}

	// Fast path: check if already sorted and non-overlapping.
	sorted := true
	for i := 1; i < len(ps.pr); i++ {
		if (ps.pr)[i].min <= (ps.pr)[i-1].max {
			sorted = false
			break
		}
	}
	if !sorted {
		sort.Slice(ps.pr, func(i, j int) bool {
			return (ps.pr)[i].min < (ps.pr)[j].min
		})
	}

	// Merge overlapping or adjacent ranges.
	merged := (ps.pr)[:1]
	for _, r := range (ps.pr)[1:] {
		last := &merged[len(merged)-1]
		if r.min <= last.max {
			// Overlapping or adjacent; extend the last range.
			if r.max > last.max {
				last.max = r.max
			}
		} else {
			// Disjoint; start a new range.
			merged = append(merged, r)
		}
	}
	ps.pr = merged
}

func (ps PortSet) String() string {
	if len(ps.pr) == 0 {
		return "none"
	}
	if len(ps.pr) == 1 && ps.pr[0].min == 0 && ps.pr[0].max == math.MaxUint16 {
		return "any"
	}
	var sb strings.Builder
	for i, pr := range ps.pr {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(pr.String())
	}
	return sb.String()
}

func ParsePortSet(s string) (PortSet, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "none" {
		return PortSet{}, nil
	}

	var ranges []PortRange
	for _, part := range strings.Split(s, ",") {
		pr, err := ParsePortRange(part)
		if err != nil {
			return PortSet{}, err
		}
		ranges = append(ranges, pr)
	}

	set := PortSet{
		pr: ranges,
	}
	set.optimize()
	return set, nil
}

func (ps PortSet) MarshalJSON() ([]byte, error) {
	return []byte(`"` + ps.String() + `"`), nil
}

func (ps *PortSet) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	parsed, err := ParsePortSet(s)
	if err != nil {
		return err
	}
	*ps = parsed
	return nil
}
