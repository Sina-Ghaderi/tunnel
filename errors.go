package tunnel

import "errors"

var (
	ErrShortPacket      = errors.New("write a short ipv4 or ipv6 packet")
	ErrFragmentedPacket = errors.New("write a fragmented ipv4 or ipv6 packet")
)
