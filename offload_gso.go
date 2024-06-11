//go:build linux

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))
const ipVersion4 = 0x04
const ipVersion6 = 0x06

const ipv4SrcAddrOffset = 0x0c
const ipv6SrcAddrOffset = 0x08

const tcpFlagsOffset = 0x0d
const (
	tcpFlagFIN uint8 = 0x01
	tcpFlagPSH uint8 = 0x08
	tcpFlagACK uint8 = 0x10
)
const (
	minIPv4packetSize = 20
	minIPv6packetSize = 40
)

type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func (v *virtioNetHdr) decodeVirtioHeader(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return errors.New("decode VirtioHeader: short buffer")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)),
		virtioNetHdrLen), b[:virtioNetHdrLen])
	return nil
}

func (v *virtioNetHdr) encodeVirtioHeader(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return errors.New("encode VirtioHeader: short buffer")
	}
	copy(b[:virtioNetHdrLen],
		unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

func (p *tunDevice) virtioRead(index int) (int, error) {

	buff := p.r_buff.virtbuff[:index]
	var hdr virtioNetHdr
	if err := hdr.decodeVirtioHeader(buff); err != nil {
		return 0, err
	}

	buff = buff[virtioNetHdrLen:]
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		if hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			gsoNoneChecksum(buff, hdr.csumStart, hdr.csumOffset)
		}

		alloc := len(buff) - len(p.r_buff.copybuff)
		if alloc > 0 {
			p.r_buff.copybuff = append(p.r_buff.copybuff, make([]byte, alloc)...)
			p.r_buff.copybuff = p.r_buff.copybuff[:cap(p.r_buff.copybuff)]
		}
		return copy(p.r_buff.copybuff, buff), nil
	}

	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 &&
		hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 &&
		hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		return 0, fmt.Errorf("tunnel: virtio read: unsupported virtio gso type: %d", hdr.gsoType)
	}

	ipversion := buff[0] >> 4
	switch ipversion {
	case ipVersion4:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 &&
			hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("tunnel: virtio read: ip header version: %d, gso type: %d",
				ipversion, hdr.gsoType)
		}

	case ipVersion6:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 &&
			hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("tunnel: virtio read: ip header version: %d, gso type: %d",
				ipversion, hdr.gsoType)
		}

	default:
		return 0, fmt.Errorf("tunnel: virtio read: invalid ip header version: %d", ipversion)
	}

	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.hdrLen = hdr.csumStart + 8
	} else {
		if len(buff) <= int(hdr.csumStart+12) {
			return 0, errors.New("tunnel: virtio read: packet is too short")
		}
		tcpHLen := uint16(buff[hdr.csumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			return 0, fmt.Errorf("tunnel: virtio read: tcp header len is invalid: %d", tcpHLen)
		}
		hdr.hdrLen = hdr.csumStart + tcpHLen
	}

	if len(buff) < int(hdr.hdrLen) {
		return 0, fmt.Errorf(
			"tunnel: virtio read: length of packet (%d) is shorter than hdrLen (%d)",
			len(buff), hdr.hdrLen)
	}

	if hdr.hdrLen < hdr.csumStart {
		return 0, fmt.Errorf("tunnel: virtio read: hdrLen (%d) is shorter than csumStart (%d)",
			hdr.hdrLen, hdr.csumStart)
	}

	csumat := int(hdr.csumStart + hdr.csumOffset)
	if csumat+1 >= len(buff) {
		return 0, fmt.Errorf(
			"tunnel: virtio read: end of checksum offset (%d) exceeds packet length (%d)",
			csumat+1, len(buff))
	}

	return p.virtioSplitGso(buff, hdr)
}

func (p *tunDevice) virtioSplitGso(buff []byte, hdr virtioNetHdr) (int, error) {
	packetv6 := buff[0]>>4 == ipVersion6
	iphLen := int(hdr.csumStart)
	sourceAddrOffset := ipv6SrcAddrOffset
	addrLen := net.IPv6len

	if !packetv6 {
		buff[10], buff[11] = 0x0, 0x0
		sourceAddrOffset = ipv4SrcAddrOffset
		addrLen = net.IPv4len
	}

	transportCsumAt := int(hdr.csumStart + hdr.csumOffset)
	buff[transportCsumAt], buff[transportCsumAt+1] = 0x0, 0x0

	var firstTCPSeqNum uint32
	var protocol uint8
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV4 ||
		hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV6 {
		protocol = unix.IPPROTO_TCP
		firstTCPSeqNum = binary.BigEndian.Uint32(buff[hdr.csumStart+4:])
	} else {
		protocol = unix.IPPROTO_UDP
	}
	nextSegmentDataAt := int(hdr.hdrLen)
	var num_bytes int

	for i := 0; nextSegmentDataAt < len(buff); i++ {
		nextSegmentEnd := nextSegmentDataAt + int(hdr.gsoSize)
		if nextSegmentEnd > len(buff) {
			nextSegmentEnd = len(buff)
		}

		segmentDataLen := nextSegmentEnd - nextSegmentDataAt
		totalLen := int(hdr.hdrLen) + segmentDataLen
		alloc_pt := num_bytes + totalLen

		if alloc_pt > len(p.r_buff.copybuff) {
			alloc := int(math.Max(float64(alloc_pt-len(p.r_buff.copybuff)), rcv_buffLen))
			p.r_buff.copybuff = append(p.r_buff.copybuff, make([]byte, alloc)...)
			p.r_buff.copybuff = p.r_buff.copybuff[:cap(p.r_buff.copybuff)]
		}

		packet_pos := p.r_buff.copybuff[num_bytes:]
		num_bytes = alloc_pt
		copy(packet_pos, buff[:iphLen])

		switch {
		case packetv6:
			binary.BigEndian.PutUint16(packet_pos[4:], uint16(totalLen-iphLen))
		default:
			if i > 0 {
				id := binary.BigEndian.Uint16(packet_pos[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(packet_pos[4:], id)
			}
			binary.BigEndian.PutUint16(packet_pos[2:], uint16(totalLen))
			ipv4CSum := ^checksum(packet_pos[:iphLen], 0)
			binary.BigEndian.PutUint16(packet_pos[10:], ipv4CSum)
		}

		copy(packet_pos[hdr.csumStart:hdr.hdrLen],
			buff[hdr.csumStart:hdr.hdrLen])

		switch protocol {
		case unix.IPPROTO_TCP:
			tcpSeq := firstTCPSeqNum + uint32(hdr.gsoSize*uint16(i))
			binary.BigEndian.PutUint32(packet_pos[hdr.csumStart+4:], tcpSeq)
			if nextSegmentEnd != len(buff) {
				clearFlags := tcpFlagFIN | tcpFlagPSH
				packet_pos[hdr.csumStart+tcpFlagsOffset] &^= clearFlags
			}
		default:
			binary.BigEndian.PutUint16(packet_pos[hdr.csumStart+4:],
				uint16(segmentDataLen)+(hdr.hdrLen-hdr.csumStart))
		}

		copy(packet_pos[hdr.hdrLen:], buff[nextSegmentDataAt:nextSegmentEnd])

		transportHeaderLen := int(hdr.hdrLen - hdr.csumStart)
		lenForPseudo := uint16(transportHeaderLen + segmentDataLen)
		transportCSumNoFold := pseudoHeaderChecksumNoFold(protocol,
			buff[sourceAddrOffset:sourceAddrOffset+addrLen],
			buff[sourceAddrOffset+addrLen:sourceAddrOffset+addrLen*2],
			lenForPseudo)

		transportCSum := ^checksum(
			packet_pos[hdr.csumStart:totalLen], transportCSumNoFold)
		binary.BigEndian.PutUint16(
			packet_pos[hdr.csumStart+hdr.csumOffset:], transportCSum)

		nextSegmentDataAt += int(hdr.gsoSize)
	}

	return num_bytes, nil
}
