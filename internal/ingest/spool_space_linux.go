package ingest

import (
	"os"
	"syscall"
)

func spoolFilesystemSpace(file *os.File) (spoolSpace, error) {
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(file.Fd()), &stat); err != nil {
		return spoolSpace{}, err
	}
	return spoolSpaceFromBlocks(stat.Blocks, stat.Bavail, stat.Frsize)
}
