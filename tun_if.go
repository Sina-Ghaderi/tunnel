//go:build linux

package tunnel

import "io"

type Config struct {
	Name          string             // Name of the tunnel interface (e.g., "tun0")
	Persist       bool               // Whether the tunnel interface should persist (remain after being closed)
	Permissions   *DevicePermissions // Permissions for the tunnel device
	MultiQueue    bool               // Whether to enable multi-queue support
	DisableGsoGro bool               // Whether to disable gso/gro and VnetHDR
}

type DevicePermissions struct {
	Owner uint // UID of the owner
	Group uint // GID of the group
}

type Iface struct {
	io.ReadWriteCloser
	platformMethods
}

var zeroConfig Config

func defaltOSparms() Config { return Config{} }

func New(config Config) (*Iface, error) {

	if config == zeroConfig {
		config = defaltOSparms()
	}
	return openDevice(config)
}
