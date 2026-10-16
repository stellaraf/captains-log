package ingest

import (
	"errors"
	"fmt"
	"math"
)

// Preserve space for checkpoints and database recovery independently of the
// configured WAL size cap. This is admission control, not a filesystem quota;
// other processes can consume space after an observation.
const SpoolFilesystemReserveBytes uint64 = 256 << 20
const spoolMetadataHeadroom uint64 = 64 << 10

var ErrSpoolHeadroom = errors.New("durable spool filesystem reserve reached")
var ErrSpoolSpaceUnknown = errors.New("durable spool filesystem space cannot be verified")

type spoolSpace struct {
	available uint64
	blockSize uint64
}

// Bavail is the space available to an unprivileged writer, unlike Bfree.
// Validate the native signed block size and unsigned counters before arithmetic.
func spoolSpaceFromBlocks(blocks, available uint64, blockSize int64) (spoolSpace, error) {
	if blockSize <= 0 || blockSize > 1<<30 || blocks == 0 || available > blocks || blocks > math.MaxUint64/uint64(blockSize) {
		return spoolSpace{}, errors.New("invalid filesystem space counters")
	}
	return spoolSpace{available: available * uint64(blockSize), blockSize: uint64(blockSize)}, nil
}

func spoolAdmissionHeld(err error) bool {
	return errors.Is(err, ErrSpoolFull) || errors.Is(err, ErrSpoolHeadroom) || errors.Is(err, ErrSpoolSpaceUnknown)
}

func (s *spool) checkHeadroom(recordBytes uint64) error {
	space, err := s.space(s.active)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSpoolSpaceUnknown, err)
	}
	if space.blockSize == 0 || space.blockSize > 1<<30 || recordBytes > maxRecordSize+8 {
		return fmt.Errorf("%w: invalid allocation size", ErrSpoolSpaceUnknown)
	}
	blocks := recordBytes / space.blockSize
	if recordBytes%space.blockSize != 0 {
		blocks++
	}
	allocation := blocks * space.blockSize // bounded by maxRecordSize plus one block
	required := SpoolFilesystemReserveBytes + spoolMetadataHeadroom + allocation
	if space.available < required {
		return fmt.Errorf("%w: %d available bytes; %d required for reserve and next record", ErrSpoolHeadroom, space.available, required)
	}
	return nil
}
