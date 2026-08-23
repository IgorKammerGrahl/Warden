package proxy

import (
	"io"
	"sync"
	"time"
)

// stampReader records when bytes actually arrived, which is what lets the
// latency spans start at "first byte received" rather than at "message decoded".
// The decode itself is real proxy cost — a chain can run to MAX_STACK_SIZE —
// and leaving it outside the measured span understates the baseline that M4's
// enforcement overhead is measured against.
//
// json.Decoder reads ahead, so a message can be fully buffered before its
// decode is even requested. arm/firstByte handle that: when a decode consumed
// no new bytes, the message arrived at the previous read, and lastByte is that
// time.
type stampReader struct {
	r io.Reader

	mu    sync.Mutex
	first time.Time // first byte-returning read since arm
	last  time.Time // most recent byte-returning read
}

func newStampReader(r io.Reader) *stampReader {
	return &stampReader{r: r}
}

func (s *stampReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		now := time.Now()
		s.mu.Lock()
		if s.first.IsZero() {
			s.first = now
		}
		s.last = now
		s.mu.Unlock()
	}
	return n, err
}

// arm starts a new measurement window.
func (s *stampReader) arm() {
	s.mu.Lock()
	s.first = time.Time{}
	s.mu.Unlock()
}

// firstByte is when the just-decoded message's first byte arrived. If the
// decode was served entirely from the decoder's buffer it falls back to the
// last read, which is when those buffered bytes did arrive.
func (s *stampReader) firstByte() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.first.IsZero() {
		if s.last.IsZero() {
			return time.Now()
		}
		return s.last
	}
	return s.first
}

// lastByte is when the most recent bytes arrived — for a just-decoded message,
// when its final bytes landed.
func (s *stampReader) lastByte() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last.IsZero() {
		return time.Now()
	}
	return s.last
}
