package ingest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
)

var ErrFrameTooLarge = errors.New("syslog frame exceeds configured maximum")

// ReadFrame decodes octet-counted and newline-delimited syslog. Returned bytes
// on error are the captured evidence, never a successfully decoded full frame.
func ReadFrame(r *bufio.Reader, max int) ([]byte, error) {
	if max < 1 {
		return nil, errors.New("invalid maximum frame size")
	}
	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	prefix := []byte{first}
	if first >= '1' && first <= '9' {
		for len(prefix) <= 12 {
			c, err := r.ReadByte()
			if err != nil {
				return prefix, fmt.Errorf("incomplete frame prefix: %w", err)
			}
			if c == ' ' {
				n, err := strconv.ParseUint(string(prefix), 10, 32)
				if err != nil || n > uint64(max) {
					return append(prefix, c), ErrFrameTooLarge
				}
				frame := make([]byte, n)
				read, err := io.ReadFull(r, frame)
				if err != nil {
					return frame[:read], fmt.Errorf("incomplete octet-counted frame: %w", err)
				}
				return frame, nil
			}
			prefix = append(prefix, c)
			if c < '0' || c > '9' {
				break
			}
		}
	}
	for {
		if prefix[len(prefix)-1] == '\n' {
			body := prefix[:len(prefix)-1]
			if len(body) > 0 && body[len(body)-1] == '\r' {
				body = body[:len(body)-1]
			}
			return body, nil
		}
		if len(prefix) > max {
			return prefix, ErrFrameTooLarge
		}
		b, err := r.ReadByte()
		if err != nil {
			return prefix, fmt.Errorf("unterminated newline frame: %w", err)
		}
		prefix = append(prefix, b)
	}
}
