package probe

import (
	"errors"
	"syscall"
)

// WSAECONNREFUSED is not exported by the frozen syscall package.
const wsaConnRefused syscall.Errno = 10061

func isRefused(err error) bool { return errors.Is(err, wsaConnRefused) }
func isReset(err error) bool {
	return errors.Is(err, syscall.WSAECONNRESET) || errors.Is(err, syscall.EPIPE)
}
