//go:build linux

package hostcontrol

import (
	"context"
	"net"
	"os"
	"syscall"
)

func dialProtected(ctx context.Context) (net.Conn, error) {
	for _, path := range []string{"/", "/run", "/run/nebulalog-control", SocketPath} {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, ErrUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnavailable
		}
		switch path {
		case SocketPath:
			if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 || st.Gid != 20002 {
				return nil, ErrUnavailable
			}
		case "/run/nebulalog-control":
			if !info.IsDir() || info.Mode().Perm() != 0750 || st.Gid != 20002 {
				return nil, ErrUnavailable
			}
		default:
			if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
				return nil, ErrUnavailable
			}
		}
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return nil, ErrUnavailable
	}
	u, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, ErrUnavailable
	}
	raw, err := u.SyscallConn()
	valid := false
	if err == nil {
		err = raw.Control(func(fd uintptr) {
			cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			valid = e == nil && cred.Uid == 0 && cred.Gid == 0 && cred.Pid > 0
		})
	}
	if err != nil || !valid {
		conn.Close()
		return nil, ErrUnavailable
	}
	return conn, nil
}
