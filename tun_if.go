//go:build linux

package tun

import "io"

type Config struct {
	Name          string
	Persist       bool
	Permissions   *DevicePermissions
	MultiQueue    bool
	DisableVetHDR bool
}

type DevicePermissions struct {
	Owner uint
	Group uint
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
