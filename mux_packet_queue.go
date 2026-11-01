package vmess

import (
	"io"
	"sync"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// One session-wide limit bounds queued payloads even when the peer creates many
// streams. The receive loop blocks when either limit is reached; packets are
// never dropped to make room. A handed-off packet belongs to its reader.
type muxPacketBudget struct {
	sync.Mutex
	writable *sync.Cond
	queued   int
	queues   map[*muxPacketQueue]struct{}
	closed   bool
	err      error
}

type muxPacket struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

type muxPacketQueue struct {
	budget     *muxPacketBudget
	readable   *sync.Cond
	items      [muxPacketQueueSize]muxPacket
	head, size int
	closed     bool
	err        error
	options    N.ReadWaitOptions
}

func newMuxPacketQueue(budget *muxPacketBudget) *muxPacketQueue {
	budget.Lock()
	defer budget.Unlock()
	if budget.writable == nil {
		budget.writable = sync.NewCond(budget)
		budget.queues = make(map[*muxPacketQueue]struct{})
	}
	queue := &muxPacketQueue{budget: budget, readable: sync.NewCond(budget), closed: budget.closed, err: budget.err}
	if !queue.closed {
		budget.queues[queue] = struct{}{}
	}
	return queue
}

func (q *muxPacketQueue) setOptions(options N.ReadWaitOptions) {
	q.budget.Lock()
	q.options = options
	q.budget.Unlock()
}

func (q *muxPacketQueue) readOptions() N.ReadWaitOptions {
	q.budget.Lock()
	defer q.budget.Unlock()
	return q.options
}

// push consumes the packet on both success and failure.
func (q *muxPacketQueue) push(packet muxPacket) error {
	q.budget.Lock()
	defer q.budget.Unlock()
	for !q.closed && (q.size == len(q.items) || q.budget.queued == muxSessionQueuedPackets) {
		q.budget.writable.Wait()
	}
	if q.closed {
		packet.buffer.Release()
		return q.err
	}
	q.items[(q.head+q.size)%len(q.items)] = packet
	q.size++
	q.budget.queued++
	q.readable.Signal()
	return nil
}

func (q *muxPacketQueue) pop() (muxPacket, error) {
	q.budget.Lock()
	defer q.budget.Unlock()
	for q.size == 0 && !q.closed {
		q.readable.Wait()
	}
	if q.size == 0 {
		return muxPacket{}, q.err
	}
	packet := q.items[q.head]
	q.items[q.head] = muxPacket{}
	q.head = (q.head + 1) % len(q.items)
	q.size--
	q.budget.queued--
	if q.closed && q.size == 0 {
		delete(q.budget.queues, q)
	}
	q.budget.writable.Broadcast()
	return packet, nil
}

// Remote EOF preserves packets already received. Local close/cancellation
// discards and releases pending packets, including after a previous EOF.
func (q *muxPacketQueue) close(err error, discard bool) {
	q.budget.Lock()
	defer q.budget.Unlock()
	q.closeLocked(err, discard)
}

func (q *muxPacketQueue) closeLocked(err error, discard bool) {
	if !q.closed {
		q.closed = true
		if err == nil {
			err = io.EOF
		}
		q.err = err
	}
	if discard {
		for q.size > 0 {
			q.items[q.head].buffer.Release()
			q.items[q.head] = muxPacket{}
			q.head = (q.head + 1) % len(q.items)
			q.size--
			q.budget.queued--
		}
	}
	if q.size == 0 {
		delete(q.budget.queues, q)
	}
	q.readable.Broadcast()
	q.budget.writable.Broadcast()
}

func (b *muxPacketBudget) close(err error, discard bool) {
	b.Lock()
	defer b.Unlock()
	if err == nil {
		err = io.EOF
	}
	b.closed, b.err = true, err
	for queue := range b.queues {
		queue.closeLocked(err, discard)
	}
}

func (b *muxPacketBudget) waitDrained() {
	b.Lock()
	defer b.Unlock()
	for b.queued != 0 {
		b.writable.Wait()
	}
}
