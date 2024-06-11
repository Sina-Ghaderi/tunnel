//go:build !linux

package tun

import "fmt"

type Config struct{}
type Iface struct{}

func New(config Config) (*Iface, error) {
	return &Iface{}, fmt.Errorf("tunnel: unsupported operation system")
}
