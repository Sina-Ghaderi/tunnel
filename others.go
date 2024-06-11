//go:build !linux

package tunnel

import (
	"fmt"
)

type Config struct{}
type Iface struct{}

func New(config Config) (*Iface, error) {
	return nil, fmt.Errorf("tunnel: unsupported operation system")
}
