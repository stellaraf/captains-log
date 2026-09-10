//go:build !linux

package hostcontrol

import (
	"context"
	"net"
)

func dialProtected(context.Context) (net.Conn, error) { return nil, ErrUnavailable }
