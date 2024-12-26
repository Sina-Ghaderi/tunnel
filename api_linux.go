//go:build linux

package tunnel

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const tunModuleCharPath = "/dev/net/tun"
const tcpOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
const udpOffloads = unix.TUN_F_USO4 | unix.TUN_F_USO6
const maxPacketLen = 1<<16 - 1
const virtioBuffLen = maxPacketLen + virtioNetHdrLen

const rcveBuffLen = 1 << 14
const sendBuffLen = 1 << 14
const pktBuffArrs = 1 << 6

type readWriteHandler [2]func(*tunDevice, []byte) (int, error)
type readBuffers struct {
	virtbuff,
	copybuff, unreadPtr []byte
}

type writeBuffers struct {
	virtbuff    []byte
	pktsbuff    [][]byte
	pktIndex    []int
	buff_pos    int
	tcpGroTable *tcpGROTable
	udpGroTable *udpGROTable
}

type platformMethods struct{ name string }
type tunDevice struct {
	rwHandler     readWriteHandler
	tunReadMux    sync.Mutex
	tunWriteMux   sync.Mutex
	file          *os.File
	r_buff        *readBuffers
	w_buff        *writeBuffers
	udpGsoEnabled bool
}

func (iface platformMethods) Name() string { return iface.name }

func (dev *tunDevice) Read(b []byte) (int, error)  { return dev.rwHandler[0](dev, b) }
func (dev *tunDevice) Write(b []byte) (int, error) { return dev.rwHandler[1](dev, b) }
func (dev *tunDevice) Close() error                { return dev.file.Close() }

func genericRead(dev *tunDevice, buff []byte) (int, error)  { return dev.file.Read(buff) }
func genericWrite(dev *tunDevice, buff []byte) (int, error) { return dev.file.Write(buff) }

func openDevice(config Config) (iface *Iface, err error) {

	nfd, err := unix.Open(tunModuleCharPath, unix.O_CLOEXEC|unix.O_RDWR, 0)
	if err != nil {
		return iface, fmt.Errorf("tunnel: open %s: %v", tunModuleCharPath, err)
	}

	iface, err = setupTunDevice(nfd, config)
	if err != nil {
		unix.Close(nfd)
	}

	return
}

func setupTunDevice(nfd int, config Config) (*Iface, error) {
	ifreq, err := unix.NewIfreq(config.Name)
	if err != nil {
		return nil, fmt.Errorf("tunnel: create iface: %v", err)
	}

	var flags uint16 = unix.IFF_NO_PI | unix.IFF_TUN

	if config.MultiQueue {
		flags |= unix.IFF_MULTI_QUEUE
	}

	if !config.DisableGsoGro {
		flags |= unix.IFF_VNET_HDR
	}

	ifreq.SetUint16(flags)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifreq)
	if err != nil {
		return nil, fmt.Errorf("tunnel: ioctl ifreq: %v", err)
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		return nil, fmt.Errorf("tunnel: set nonblock: %v", err)
	}

	if err := setDeviceOptions(nfd, config); err != nil {
		return nil, fmt.Errorf("tunnel: device option: %v", err)
	}

	iface := &Iface{platformMethods: platformMethods{name: ifreq.Name()}}
	dev := new(tunDevice)
	dev.file = os.NewFile(uintptr(nfd), ifreq.Name())

	dev.rwHandler[0], dev.rwHandler[1] = genericRead, genericWrite
	if flags&unix.IFF_VNET_HDR != 0 {
		if err := dev.setTunnelvnetHdr(iface.Name()); err != nil {
			return nil, err
		}
	}

	iface.ReadWriteCloser = dev
	return iface, nil
}

func setDeviceOptions(fd int, config Config) error {
	if config.Permissions != nil {
		own := config.Permissions.Owner
		err := unix.IoctlSetInt(fd, unix.TUNSETOWNER, int(own))
		if err != nil {
			return fmt.Errorf("set tunnel owner: %v", err)
		}

		grp := config.Permissions.Group
		err = unix.IoctlSetInt(fd, unix.TUNSETGROUP, int(grp))
		if err != nil {
			return fmt.Errorf("set tunnel group: %v", err)
		}
	}

	persistflag := 0
	if config.Persist {
		persistflag = 1
	}

	err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, persistflag)
	if err != nil {
		return fmt.Errorf("set persist flag: %v", err)
	}

	return err
}

func (p *tunDevice) setTunnelvnetHdr(name string) error {
	var vnethdr bool
	sysconn, err := p.file.SyscallConn()
	if err != nil {
		return fmt.Errorf("tunnel: syscall conn: %v", err)
	}

	if errconn := sysconn.Control(func(fd uintptr) {
		var ifReq *unix.Ifreq
		ifReq, err = unix.NewIfreq(name)
		if err != nil {
			err = fmt.Errorf("tunnel: iface request: %v", err)
			return
		}

		err = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifReq)
		if err != nil {
			err = fmt.Errorf("tunnel: ioctl get iface: %v", err)
			return
		}

		reqFlags := ifReq.Uint16()
		if reqFlags&unix.IFF_VNET_HDR != 0 {
			err = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tcpOffloads)
			if err != nil {
				err = fmt.Errorf("tunnel: set offload: %v", err)
				return
			}
			vnethdr = true
			p.udpGsoEnabled = unix.IoctlSetInt(int(fd),
				unix.TUNSETOFFLOAD, tcpOffloads|udpOffloads) == nil
			return
		}
	}); errconn != nil {
		return fmt.Errorf("tunnel: set ctrl func: %v", errconn)
	}

	if vnethdr {
		p.rwHandler[0], p.rwHandler[1] = vnetHdrRead, vnetHdrWrite
		p.r_buff, p.w_buff = new(readBuffers), new(writeBuffers)
		p.r_buff.virtbuff = make([]byte, virtioBuffLen)
		p.r_buff.copybuff = make([]byte, rcveBuffLen)
		p.w_buff.virtbuff = make([]byte, sendBuffLen)
		p.w_buff.pktsbuff = make([][]byte, 0, pktBuffArrs)
		p.w_buff.pktIndex = make([]int, 0, pktBuffArrs)
		p.w_buff.tcpGroTable = newTCPGROTable()
		p.w_buff.udpGroTable = newUDPGROTable()
	}

	return err
}

func vnetHdrRead(dev *tunDevice, buff []byte) (int, error) {
	dev.tunReadMux.Lock()
	defer dev.tunReadMux.Unlock()

	defer func() {
		if len(dev.r_buff.unreadPtr) == 0 &&
			cap(dev.r_buff.copybuff) > rcveBuffLen {
			dev.r_buff.unreadPtr = nil
			dev.r_buff.copybuff = dev.r_buff.copybuff[:rcveBuffLen:rcveBuffLen]
		}
	}()

	cp_from_buff := copy(buff, dev.r_buff.unreadPtr)
	dev.r_buff.unreadPtr = dev.r_buff.unreadPtr[cp_from_buff:]
	if cp_from_buff == len(buff) {
		return cp_from_buff, nil
	}

	index, err := dev.file.Read(dev.r_buff.virtbuff)
	if errors.Is(err, unix.EBADFD) {
		err = os.ErrClosed
	}

	if err != nil {
		return cp_from_buff, err
	}

	nb, err := dev.virtioRead(index)
	dev.r_buff.unreadPtr = dev.r_buff.copybuff[:nb]
	cp_left := copy(buff[cp_from_buff:], dev.r_buff.unreadPtr)
	dev.r_buff.unreadPtr = dev.r_buff.unreadPtr[cp_left:]
	return cp_from_buff + cp_left, err
}

func vnetHdrWrite(dev *tunDevice, buff []byte) (int, error) {
	dev.tunWriteMux.Lock()
	defer dev.tunWriteMux.Unlock()
	defer func() {
		dev.w_buff.tcpGroTable.reset()
		dev.w_buff.udpGroTable.reset()
		dev.w_buff.buff_pos = 0
		if len(dev.w_buff.virtbuff) > sendBuffLen {
			dev.w_buff.virtbuff = dev.w_buff.virtbuff[:sendBuffLen:sendBuffLen]
		}
		dev.w_buff.pktsbuff = dev.w_buff.pktsbuff[:0:pktBuffArrs]
		dev.w_buff.pktIndex = dev.w_buff.pktIndex[:0:pktBuffArrs]
	}()

	nw, err := dev.slicePackets(buff)
	if err != nil {
		return 0, err
	}
	if err := dev.virtioMakeGro(); err != nil {
		return 0, err
	}

	for _, pktIndex := range dev.w_buff.pktIndex {
		_, err := dev.file.Write(dev.w_buff.pktsbuff[pktIndex][:])
		if errors.Is(err, syscall.EBADFD) {
			return 0, os.ErrClosed
		}
		if err != nil {
			return 0, err
		}
	}
	return nw, nil
}
