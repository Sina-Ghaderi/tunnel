//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
*/

package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"golang.org/x/sys/unix"
)

type groResult int
type groCandidateType uint8
type canCoalesce int
type coalesceResult int

const (
	coalesceInsufficientCap coalesceResult = iota
	coalescePSHEnding
	coalesceItemInvalidCSum
	coalescePktInvalidCSum
	coalesceSuccess
)

const (
	notAGroCandidate groCandidateType = iota
	tcp4GroCandidate
	tcp6GroCandidate
	udp4GroCandidate
	udp6GroCandidate
)

const (
	groResultNoop groResult = iota
	groResultTableInsert
	groResultCoalesced
)

const (
	coalescePrepend canCoalesce = iota - 1
	coalesceUnavailable
	coalesceAppend
)

const ipv4FlagMoreFragments uint8 = 0x20
const udpHeaderLen = 0x08
const maxIPv4HeaderLen = 0x3c

type tcpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	rxAck            uint32
	isV6             bool
}

type tcpGROTable struct {
	itemsByFlow map[tcpFlowKey][]tcpGROItem
	itemsPool   [][]tcpGROItem
}

type tcpGROItem struct {
	key       tcpFlowKey
	sentSeq   uint32
	bufsIndex uint16
	numMerged uint16
	gsoSize   uint16
	iphLen    uint8
	tcphLen   uint8
	pshSet    bool
}

type udpGROItem struct {
	key              udpFlowKey
	bufsIndex        uint16
	numMerged        uint16
	gsoSize          uint16
	iphLen           uint8
	cSumKnownInvalid bool
}

type udpFlowKey struct {
	srcAddr, dstAddr [16]byte
	srcPort, dstPort uint16
	isV6             bool
}

type udpGROTable struct {
	itemsByFlow map[udpFlowKey][]udpGROItem
	itemsPool   [][]udpGROItem
}

var (
	errShortPacket      = errors.New("write a short ipv4 or ipv6 packet")
	errFragmentedPacket = errors.New("write a fragmented ipv4 or ipv6 packet")
)

func newUDPGROTable() *udpGROTable {
	u := &udpGROTable{
		itemsByFlow: make(map[udpFlowKey][]udpGROItem, pktBuffArrs),
		itemsPool:   make([][]udpGROItem, pktBuffArrs),
	}
	for i := range u.itemsPool {
		u.itemsPool[i] = make([]udpGROItem, 0, pktBuffArrs)
	}
	return u
}

func newUDPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset int) udpFlowKey {
	key := udpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[udphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[udphOffset+2:])
	key.isV6 = addrSize == 16
	return key
}

func (u *udpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset,
	dstAddrOffset, udphOffset, bufsIndex int) ([]udpGROItem, bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	items, ok := u.itemsByFlow[key]
	if ok {
		return items, ok
	}

	item := udpGROItem{
		key: key, bufsIndex: uint16(bufsIndex), iphLen: uint8(udphOffset),
		gsoSize:          uint16(len(pkt[udphOffset+udpHeaderLen:])),
		cSumKnownInvalid: false,
	}
	items = u.newItems()
	items = append(items, item)
	u.itemsByFlow[key] = items
	return nil, false
}

func (u *udpGROTable) insert(pkt []byte, srcAddrOffset, dstAddrOffset,
	udphOffset, bufsIndex int, cSumKnownInvalid bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	item := udpGROItem{
		key: key, bufsIndex: uint16(bufsIndex), iphLen: uint8(udphOffset),
		gsoSize:          uint16(len(pkt[udphOffset+udpHeaderLen:])),
		cSumKnownInvalid: cSumKnownInvalid,
	}
	items, ok := u.itemsByFlow[key]
	if !ok {
		items = u.newItems()
	}
	items = append(items, item)
	u.itemsByFlow[key] = items
}

func (u *udpGROTable) updateAt(item udpGROItem, i int) {
	items := u.itemsByFlow[item.key]
	items[i] = item
}

func (u *udpGROTable) newItems() []udpGROItem {
	var items []udpGROItem
	if len(u.itemsPool) == 0 {
		u.itemsPool = make([][]udpGROItem, pktBuffArrs)
		for i := range u.itemsPool {
			u.itemsPool[i] = make([]udpGROItem, 0, pktBuffArrs)
		}
	}
	items = u.itemsPool[len(u.itemsPool)-1]
	u.itemsPool = u.itemsPool[:len(u.itemsPool)-1]
	return items
}

func (u *udpGROTable) reset() {
	for k, items := range u.itemsByFlow {
		items = items[:0]
		if len(u.itemsPool) < pktBuffArrs {
			u.itemsPool = append(u.itemsPool, items)
		}

		delete(u.itemsByFlow, k)
	}
}

func newTCPGROTable() *tcpGROTable {
	t := &tcpGROTable{
		itemsByFlow: make(map[tcpFlowKey][]tcpGROItem, pktBuffArrs),
		itemsPool:   make([][]tcpGROItem, pktBuffArrs),
	}
	for i := range t.itemsPool {
		t.itemsPool[i] = make([]tcpGROItem, 0, pktBuffArrs)
	}
	return t
}

func newTCPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset int) tcpFlowKey {
	key := tcpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	key.srcPort = binary.BigEndian.Uint16(pkt[tcphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[tcphOffset+2:])
	key.rxAck = binary.BigEndian.Uint32(pkt[tcphOffset+8:])
	key.isV6 = addrSize == 16
	return key
}

func (t *tcpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset,
	tcphOffset, tcphLen, bufsIndex int) ([]tcpGROItem, bool) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	items, ok := t.itemsByFlow[key]
	if ok {
		return items, ok
	}

	item := tcpGROItem{
		key: key, bufsIndex: uint16(bufsIndex),
		gsoSize: uint16(len(pkt[tcphOffset+tcphLen:])),
		iphLen:  uint8(tcphOffset), tcphLen: uint8(tcphLen),
		sentSeq: binary.BigEndian.Uint32(pkt[tcphOffset+4:]),
		pshSet:  pkt[tcphOffset+tcpFlagsOffset]&tcpFlagPSH != 0,
	}
	items = t.newItems()
	items = append(items, item)
	t.itemsByFlow[key] = items
	return nil, false
}

func (t *tcpGROTable) insert(pkt []byte, srcAddrOffset, dstAddrOffset,
	tcphOffset, tcphLen, bufsIndex int) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	item := tcpGROItem{
		key: key, bufsIndex: uint16(bufsIndex),
		gsoSize: uint16(len(pkt[tcphOffset+tcphLen:])),
		iphLen:  uint8(tcphOffset), tcphLen: uint8(tcphLen),
		sentSeq: binary.BigEndian.Uint32(pkt[tcphOffset+4:]),
		pshSet:  pkt[tcphOffset+tcpFlagsOffset]&tcpFlagPSH != 0,
	}
	items, ok := t.itemsByFlow[key]
	if !ok {
		items = t.newItems()
	}
	items = append(items, item)
	t.itemsByFlow[key] = items
}

func (t *tcpGROTable) updateAt(item tcpGROItem, i int) {
	items := t.itemsByFlow[item.key]
	items[i] = item
}

func (t *tcpGROTable) deleteAt(key tcpFlowKey, i int) {
	items := t.itemsByFlow[key]
	items = append(items[:i], items[i+1:]...)
	t.itemsByFlow[key] = items
}

func (t *tcpGROTable) newItems() []tcpGROItem {
	var items []tcpGROItem
	if len(t.itemsPool) == 0 {
		t.itemsPool = make([][]tcpGROItem, pktBuffArrs)
		for i := range t.itemsPool {
			t.itemsPool[i] = make([]tcpGROItem, 0, pktBuffArrs)
		}
	}
	items = t.itemsPool[len(t.itemsPool)-1]
	t.itemsPool = t.itemsPool[:len(t.itemsPool)-1]
	return items
}

func (t *tcpGROTable) reset() {

	for k, items := range t.itemsByFlow {
		items = items[:0]
		if len(t.itemsPool) < pktBuffArrs {
			t.itemsPool = append(t.itemsPool, items)
		}
		delete(t.itemsByFlow, k)
	}
}

func (v *tunDevice) checkGroCandidate(b []byte) groCandidateType {

	b = b[virtioNetHdrLen:]
	if len(b) < 28 {
		return notAGroCandidate
	}
	if b[0]>>4 == ipVersion4 {
		if b[0]&0x0F != 5 {
			return notAGroCandidate
		}
		if b[9] == unix.IPPROTO_TCP && len(b) >= 40 {
			return tcp4GroCandidate
		}
		if b[9] == unix.IPPROTO_UDP && v.udpGsoEnabled {
			return udp4GroCandidate
		}
	} else if b[0]>>4 == ipVersion6 {
		if b[6] == unix.IPPROTO_TCP && len(b) >= 60 {
			return tcp6GroCandidate
		}
		if b[6] == unix.IPPROTO_UDP && len(b) >= 48 && v.udpGsoEnabled {
			return udp6GroCandidate
		}
	}
	return notAGroCandidate

}

func ipHeadersCanCoalesce(pktA, pktB []byte) bool {
	if len(pktA) < 9 || len(pktB) < 9 {
		return false
	}
	if pktA[0]>>4 == 6 {
		if pktA[0] != pktB[0] || pktA[1]>>4 != pktB[1]>>4 {
			return false
		}
		if pktA[7] != pktB[7] {
			return false
		}
	} else {
		if pktA[1] != pktB[1] {
			return false
		}
		if pktA[6]>>5 != pktB[6]>>5 {
			return false
		}
		if pktA[8] != pktB[8] {
			return false
		}
	}
	return true
}

func (v *tunDevice) bufferIPv4Packet(buff []byte) (int, error) {

	if len(buff) < minIPv4packetSize {
		return 0, errShortPacket
	}

	headerLen := int(buff[0]&0x0F) << 2
	if headerLen > maxIPv4HeaderLen || headerLen < minIPv4packetSize {
		return 0, fmt.Errorf("tunnel: virtio write: invalid ipv4 header len(%d)", headerLen)
	}

	totalLen := int(binary.BigEndian.Uint16(buff[2:]))
	if totalLen < minIPv4packetSize || totalLen > maxPacketLen {
		return 0, fmt.Errorf("tunnel: virtio write: invalid ipv4 packet len(%d)", totalLen)
	}
	if totalLen > len(buff) {
		return 0, errFragmentedPacket
	}
	return v.copyFromUser(buff, totalLen), nil
}

func (v *tunDevice) bufferIPv6Packet(buff []byte) (int, error) {
	if len(buff) < minIPv6packetSize {
		return 0, errShortPacket
	}

	payloadLen := int(binary.BigEndian.Uint16(buff[4:]))
	totalLen := payloadLen + minIPv6packetSize

	if totalLen > maxPacketLen || totalLen < minIPv6packetSize {
		return 0, fmt.Errorf("tunnel: virtio write: invalid ipv6 packet len(%d)", totalLen)
	}
	if totalLen > len(buff) {
		return 0, errFragmentedPacket
	}
	return v.copyFromUser(buff, totalLen), nil
}

func (v *tunDevice) bufferPackets(buff []byte) (int, error) {
	switch buff[0] >> 4 {
	case ipVersion4:
		done, err := v.bufferIPv4Packet(buff)
		if err != nil {
			return 0, err
		}
		return done, nil

	case ipVersion6:
		done, err := v.bufferIPv6Packet(buff)
		if err != nil {
			return 0, err
		}
		return done, nil
	}

	return 0, fmt.Errorf("tunnel: virtio write: write an invalid packet")
}

func (v *tunDevice) slicePackets(buff []byte) (int, error) {
	var nextPacketIndex int
	if len(buff) < 1 {
		return nextPacketIndex, nil
	}
	done, err := v.bufferPackets(buff)
	if err != nil {
		if err == errFragmentedPacket || err == errShortPacket {
			return nextPacketIndex, nil
		}
		return nextPacketIndex, err
	}
	nextPacketIndex += done
	buff = buff[done:]

	for len(buff) > 0 {
		done, err := v.bufferPackets(buff)
		if err != nil {
			return nextPacketIndex, nil
		}
		nextPacketIndex += done
		buff = buff[done:]
	}
	return nextPacketIndex, nil
}

func (v *tunDevice) copyFromUser(buff []byte, totalLen int) int {
	pos := v.w_buff.buff_pos + virtioNetHdrLen
	v.w_buff.growBuffer(pos + totalLen)

	ncp := copy(v.w_buff.virtbuff[pos:], buff[:totalLen])
	new_pos := ncp + virtioNetHdrLen
	onepkt := v.w_buff.virtbuff[v.w_buff.buff_pos : v.w_buff.buff_pos+new_pos]
	onepkt = onepkt[:len(onepkt):len(onepkt)]
	v.w_buff.pktsbuff = append(v.w_buff.pktsbuff, onepkt)
	v.w_buff.buff_pos += new_pos
	return ncp
}

func (vs *writeBuffers) growBuffer(alloc_size int) {
	if alloc_size <= len(vs.virtbuff) {
		return
	}

	alloc := int(math.Max(float64(alloc_size-len(vs.virtbuff)), sendBuffLen))
	arr_ptr := &vs.virtbuff[0]
	vs.virtbuff = append(vs.virtbuff, make([]byte, alloc)...)
	vs.virtbuff = vs.virtbuff[:cap(vs.virtbuff)]
	if arr_ptr == &vs.virtbuff[0] {
		return
	}
	ptr_pos := 0
	for i := 0; i < len(vs.pktsbuff); i++ {
		buff_len := ptr_pos + len(vs.pktsbuff[i])
		onepkt := vs.virtbuff[ptr_pos:buff_len]
		onepkt = onepkt[:len(onepkt):len(onepkt)]
		vs.pktsbuff[i] = onepkt
		ptr_pos = buff_len
	}
}

func (v *tunDevice) virtioMakeGro() error {
	for i := range v.w_buff.pktsbuff {
		var result groResult

		groCanDo := v.checkGroCandidate(v.w_buff.pktsbuff[i])
		switch isv6 := false; groCanDo {
		case tcp4GroCandidate:
			result = v.w_buff.tcpGRO(i, isv6)
		case tcp6GroCandidate:
			isv6 = true
			result = v.w_buff.tcpGRO(i, isv6)
		case udp4GroCandidate:
			result = v.w_buff.udpGRO(i, isv6)
		case udp6GroCandidate:
			isv6 = true
			result = v.w_buff.udpGRO(i, isv6)
		}

		switch result {
		case groResultNoop:
			hdr := virtioNetHdr{}
			err := hdr.encodeVirtioHeader(
				v.w_buff.pktsbuff[i][:])

			if err != nil {
				return err
			}
			fallthrough
		case groResultTableInsert:
			v.w_buff.pktIndex = append(v.w_buff.pktIndex, i)
		}
	}

	err_tcp := v.w_buff.applyTCPCoalesceAccounting()
	err_udp := v.w_buff.applyUDPCoalesceAccounting()
	if err_tcp != nil {
		err_tcp = fmt.Errorf("tunnel: virtio write: %v", err_tcp)
	}
	if err_udp != nil {
		err_udp = fmt.Errorf("tunnel: virtio write: %v", err_udp)
	}

	return errors.Join(err_tcp, err_udp)
}

func (vs *writeBuffers) tcpGRO(pktI int, isV6 bool) groResult {

	pkt := vs.pktsbuff[pktI][virtioNetHdrLen:]
	if len(pkt) > maxPacketLen {
		return groResultNoop
	}
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	tcphLen := int((pkt[iphLen+12] >> 4) * 4)
	if tcphLen < 20 || tcphLen > 60 {
		return groResultNoop
	}
	if len(pkt) < iphLen+tcphLen {
		return groResultNoop
	}
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 ||
			pkt[6]<<3 != 0 || pkt[7] != 0 {
			return groResultNoop
		}
	}
	tcpFlags := pkt[iphLen+tcpFlagsOffset]
	var pshSet bool
	if tcpFlags != tcpFlagACK {
		if pkt[iphLen+tcpFlagsOffset] != tcpFlagACK|tcpFlagPSH {
			return groResultNoop
		}
		pshSet = true
	}
	gsoSize := uint16(len(pkt) - tcphLen - iphLen)
	if gsoSize < 1 {
		return groResultNoop
	}
	seq := binary.BigEndian.Uint32(pkt[iphLen+4:])
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	items, existing := vs.tcpGroTable.lookupOrInsert(pkt,
		srcAddrOffset, srcAddrOffset+addrLen, iphLen, tcphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	for i := len(items) - 1; i >= 0; i-- {
		item := items[i]
		can := vs.tcpPacketsCanCoalesce(pkt, uint8(iphLen),
			uint8(tcphLen), seq, pshSet, gsoSize, &item)
		if can != coalesceUnavailable {
			result := vs.coalesceTCPPackets(
				can, pkt, pktI, gsoSize, seq, pshSet, &item, isV6)
			switch result {
			case coalesceSuccess:
				vs.tcpGroTable.updateAt(item, i)
				return groResultCoalesced
			case coalesceItemInvalidCSum:
				vs.tcpGroTable.deleteAt(item.key, i)
			case coalescePktInvalidCSum:
				return groResultNoop
			default:
			}
		}
	}
	vs.tcpGroTable.insert(pkt, srcAddrOffset,
		srcAddrOffset+addrLen, iphLen, tcphLen, pktI)
	return groResultTableInsert
}

func (vs *writeBuffers) tcpPacketsCanCoalesce(pkt []byte, iphLen, tcphLen uint8,
	seq uint32, pshSet bool, gsoSize uint16, item *tcpGROItem) canCoalesce {

	pktTarget := vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:]
	if tcphLen != item.tcphLen {
		return coalesceUnavailable
	}
	if tcphLen > 20 {
		if !bytes.Equal(pkt[iphLen+20:iphLen+tcphLen],
			pktTarget[item.iphLen+20:iphLen+tcphLen]) {
			return coalesceUnavailable
		}
	}
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	lhsLen := item.gsoSize
	lhsLen += item.numMerged * item.gsoSize
	if seq == item.sentSeq+uint32(lhsLen) {
		if item.pshSet {
			return coalesceUnavailable
		}
		if len(pktTarget[iphLen+tcphLen:])%int(item.gsoSize) != 0 {
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize {
			return coalesceUnavailable
		}
		return coalesceAppend
	} else if seq+uint32(gsoSize) == item.sentSeq {
		if pshSet {
			return coalesceUnavailable
		}
		if gsoSize < item.gsoSize {
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize && item.numMerged > 0 {
			return coalesceUnavailable
		}
		return coalescePrepend
	}
	return coalesceUnavailable
}

func (vs *writeBuffers) coalesceTCPPackets(mode canCoalesce, pkt []byte, pktBuffsIndex int,
	gsoSize uint16, seq uint32, pshSet bool, item *tcpGROItem, isV6 bool) coalesceResult {

	var pktHead []byte
	headersLen := item.iphLen + item.tcphLen
	coalescedLen := len(vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:]) +
		len(pkt) - int(headersLen)
	if mode == coalescePrepend {
		pktHead = pkt
		if cap(pkt)-virtioNetHdrLen < coalescedLen {
			return coalesceInsufficientCap
		}
		if pshSet {
			return coalescePSHEnding
		}
		if item.numMerged == 0 {
			if !checksumValid(vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:],
				item.iphLen, unix.IPPROTO_TCP, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidCSum
		}
		item.sentSeq = seq
		extendBy := coalescedLen - len(pktHead)
		vs.pktsbuff[pktBuffsIndex] =
			append(vs.pktsbuff[pktBuffsIndex], make([]byte, extendBy)...)
		copy(vs.pktsbuff[pktBuffsIndex][virtioNetHdrLen+len(pkt):],
			vs.pktsbuff[item.bufsIndex][virtioNetHdrLen+int(headersLen):])
		vs.pktsbuff[item.bufsIndex] = vs.pktsbuff[pktBuffsIndex]
		vs.pktsbuff[pktBuffsIndex] = vs.pktsbuff[item.bufsIndex]
	} else {
		pktHead = vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:]
		if cap(pktHead)-virtioNetHdrLen < coalescedLen {
			return coalesceInsufficientCap
		}
		if item.numMerged == 0 {
			if !checksumValid(vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:],
				item.iphLen, unix.IPPROTO_TCP, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidCSum
		}
		if pshSet {
			item.pshSet = pshSet
			pktHead[item.iphLen+tcpFlagsOffset] |= tcpFlagPSH
		}
		extendBy := len(pkt) - int(headersLen)
		vs.pktsbuff[item.bufsIndex] =
			append(vs.pktsbuff[item.bufsIndex], make([]byte, extendBy)...)
		copy(vs.pktsbuff[item.bufsIndex][virtioNetHdrLen+len(pktHead):], pkt[headersLen:])
	}

	if gsoSize > item.gsoSize {
		item.gsoSize = gsoSize
	}

	item.numMerged++
	return coalesceSuccess
}

func (vs *writeBuffers) applyTCPCoalesceAccounting() error {

	for _, items := range vs.tcpGroTable.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
					hdrLen:     uint16(item.iphLen + item.tcphLen),
					gsoSize:    item.gsoSize,
					csumStart:  uint16(item.iphLen),
					csumOffset: 16,
				}
				pkt := vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:]
				if item.key.isV6 {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV6
					binary.BigEndian.PutUint16(pkt[4:],
						uint16(len(pkt))-uint16(item.iphLen))
				} else {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
					pkt[10], pkt[11] = 0, 0
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
					iphCSum := ^checksum(pkt[:item.iphLen], 0)
					binary.BigEndian.PutUint16(pkt[10:], iphCSum)
				}
				err := hdr.encodeVirtioHeader(vs.pktsbuff[item.bufsIndex][:])
				if err != nil {
					return err
				}
				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				srcAddrAt := virtioNetHdrLen + addrOffset
				srcAddr := vs.pktsbuff[item.bufsIndex][srcAddrAt : srcAddrAt+addrLen]
				dstAddr := vs.pktsbuff[item.bufsIndex][srcAddrAt+addrLen : srcAddrAt+addrLen*2]
				psum := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP,
					srcAddr, dstAddr, uint16(len(pkt)-int(item.iphLen)))
				binary.BigEndian.PutUint16(
					pkt[hdr.csumStart+hdr.csumOffset:], checksum([]byte{}, psum))
			} else {
				hdr := virtioNetHdr{}
				err := hdr.encodeVirtioHeader(vs.pktsbuff[item.bufsIndex][:])
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (vs *writeBuffers) udpGRO(pktI int, isV6 bool) groResult {
	pkt := vs.pktsbuff[pktI][virtioNetHdrLen:]
	if len(pkt) > maxPacketLen {
		return groResultNoop
	}
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	if len(pkt) < iphLen+udpHeaderLen {
		return groResultNoop
	}
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 ||
			pkt[6]<<3 != 0 || pkt[7] != 0 {
			return groResultNoop
		}
	}
	gsoSize := uint16(len(pkt) - udpHeaderLen - iphLen)
	if gsoSize < 1 {
		return groResultNoop
	}
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	items, existing := vs.udpGroTable.lookupOrInsert(
		pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	item := items[len(items)-1]
	can := vs.udpPacketsCanCoalesce(pkt, uint8(iphLen), gsoSize, &item)
	var pktCSumKnownInvalid bool
	if can == coalesceAppend {
		result := vs.coalesceUDPPackets(pkt, &item, isV6)
		switch result {
		case coalesceSuccess:
			vs.udpGroTable.updateAt(item, len(items)-1)
			return groResultCoalesced
		case coalesceItemInvalidCSum:
		case coalescePktInvalidCSum:
			pktCSumKnownInvalid = true
		default:
		}
	}
	vs.udpGroTable.insert(pkt, srcAddrOffset, srcAddrOffset+addrLen,
		iphLen, pktI, pktCSumKnownInvalid)
	return groResultTableInsert
}

func (vs *writeBuffers) udpPacketsCanCoalesce(pkt []byte, iphLen uint8, gsoSize uint16,
	item *udpGROItem) canCoalesce {
	pktTarget := vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:]
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	if len(pktTarget[iphLen+udpHeaderLen:])%int(item.gsoSize) != 0 {
		return coalesceUnavailable
	}
	if gsoSize > item.gsoSize {
		return coalesceUnavailable
	}
	return coalesceAppend
}

func (vs *writeBuffers) coalesceUDPPackets(pkt []byte, item *udpGROItem, isV6 bool) coalesceResult {
	pktHead := vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:]
	headersLen := item.iphLen + udpHeaderLen
	coalescedLen := len(vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:]) +
		len(pkt) - int(headersLen)

	if cap(pktHead)-virtioNetHdrLen < coalescedLen {
		return coalesceInsufficientCap
	}
	if item.numMerged == 0 {
		if item.cSumKnownInvalid ||
			!checksumValid(vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:],
				item.iphLen, unix.IPPROTO_UDP, isV6) {
			return coalesceItemInvalidCSum
		}
	}
	if !checksumValid(pkt, item.iphLen, unix.IPPROTO_UDP, isV6) {
		return coalescePktInvalidCSum
	}
	extendBy := len(pkt) - int(headersLen)
	vs.pktsbuff[item.bufsIndex] = append(vs.pktsbuff[item.bufsIndex], make([]byte, extendBy)...)
	copy(vs.pktsbuff[item.bufsIndex][virtioNetHdrLen+len(pktHead):], pkt[headersLen:])

	item.numMerged++
	return coalesceSuccess
}

func (vs *writeBuffers) applyUDPCoalesceAccounting() error {
	for _, items := range vs.udpGroTable.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					flags:     unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
					hdrLen:    uint16(item.iphLen + udpHeaderLen),
					gsoSize:   item.gsoSize,
					csumStart: uint16(item.iphLen), csumOffset: 6,
				}
				pkt := vs.pktsbuff[item.bufsIndex][virtioNetHdrLen:]
				hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_UDP_L4
				if item.key.isV6 {
					binary.BigEndian.PutUint16(pkt[4:],
						uint16(len(pkt))-uint16(item.iphLen))
				} else {
					pkt[10], pkt[11] = 0, 0
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
					iphCSum := ^checksum(pkt[:item.iphLen], 0)
					binary.BigEndian.PutUint16(pkt[10:], iphCSum)
				}
				err := hdr.encodeVirtioHeader(
					vs.pktsbuff[item.bufsIndex][:])
				if err != nil {
					return err
				}
				binary.BigEndian.PutUint16(pkt[item.iphLen+4:],
					uint16(len(pkt[item.iphLen:])))
				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				srcAddrAt := virtioNetHdrLen + addrOffset
				srcAddr := vs.pktsbuff[item.bufsIndex][srcAddrAt : srcAddrAt+addrLen]
				dstAddr := vs.pktsbuff[item.bufsIndex][srcAddrAt+addrLen : srcAddrAt+addrLen*2]
				psum := pseudoHeaderChecksumNoFold(unix.IPPROTO_UDP, srcAddr,
					dstAddr, uint16(len(pkt)-int(item.iphLen)))
				binary.BigEndian.PutUint16(pkt[hdr.csumStart+hdr.csumOffset:],
					checksum([]byte{}, psum))
			} else {
				hdr := virtioNetHdr{}
				err := hdr.encodeVirtioHeader(vs.pktsbuff[item.bufsIndex][:])
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
