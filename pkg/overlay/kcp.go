package overlay

import (
	"encoding/binary"
	"errors"
	"sync"
)

// KCP commands
const (
	IKCP_CMD_PUSH uint8 = 81 // cmd: push data
	IKCP_CMD_ACK  uint8 = 82 // cmd: ack
	IKCP_CMD_WASK uint8 = 83 // cmd: window probe (ask)
	IKCP_CMD_WINS uint8 = 84 // cmd: window size (tell)

	IKCP_RTO_NDL uint32 = 20   // no-delay min rto (20ms)
	IKCP_RTO_MIN uint32 = 40   // normal min rto
	IKCP_RTO_DEF uint32 = 100  // default rto (100ms)
	IKCP_RTO_MAX uint32 = 5000 // max rto (5000ms)

	IKCP_WND_SND uint16 = 128
	IKCP_WND_RCV uint16 = 256

	// Backpressure thresholds (matches Browser SCTP Backpressure Valve)
	BackpressureLowWater  = 0
	BackpressureMidWater  = 64 * 1024 // 64 KB
)

// BackpressureMode represents the 3-level SCTP backpressure valve state.
type BackpressureMode int

const (
	BackpressureTurbo    BackpressureMode = 0 // bufferedAmount == 0: Fast retransmit + normal RTO
	BackpressureMild     BackpressureMode = 1 // 0 < bufferedAmount <= 64KB: No FEC, RTO * 1.5x
	BackpressureCircuit  BackpressureMode = 2 // bufferedAmount > 64KB: Suspend retransmit timer, pause writes
)

var (
	ErrBackpressureCircuitOpen = errors.New("kcp: SCTP backpressure valve in circuit-breaker mode (>64KB)")
	ErrInvalidKCPSegment       = errors.New("kcp: invalid segment framing")
)

type kcpSegment struct {
	conv     uint32
	cmd      uint8
	frg      uint8
	wnd      uint16
	ts       uint32
	sn       uint32
	una      uint32
	rto      uint32
	xmit     uint32
	fastack  uint32
	resendts uint32
	data     []byte
}

func (seg *kcpSegment) encodeHeader(ptr []byte) {
	binary.LittleEndian.PutUint32(ptr[0:4], seg.conv)
	ptr[4] = seg.cmd
	ptr[5] = seg.frg
	binary.LittleEndian.PutUint16(ptr[6:8], seg.wnd)
	binary.LittleEndian.PutUint32(ptr[8:12], seg.ts)
	binary.LittleEndian.PutUint32(ptr[12:16], seg.sn)
	binary.LittleEndian.PutUint32(ptr[16:20], seg.una)
	binary.LittleEndian.PutUint32(ptr[20:24], uint32(len(seg.data)))
}

// KCPSession is a thread-safe, Sans-IO KCP ARQ state machine locked to the
// 1180-byte Overlay payload ceiling (1140-byte MSS when 16-byte E2EE tag is active).
type KCPSession struct {
	mu       sync.Mutex
	conv     uint32
	mtu      int
	mss      int
	sndUna   uint32
	sndNxt   uint32
	rcvNxt   uint32
	rxSrtt   int32
	rxRttval int32
	rxRto    uint32
	rxMinrto uint32
	sndWnd   uint16
	rcvWnd   uint16
	rmtWnd   uint16
	cwnd     uint16
	current  uint32
	interval uint32
	tsFlush  uint32
	nodelay  bool
	updated  bool
	fastResend uint32
	nocwnd     bool

	sndQueue []kcpSegment
	rcvQueue []kcpSegment
	sndBuf   []kcpSegment
	rcvBuf   []kcpSegment
	acklist  [][2]uint32 // [sn, ts]

	backpressureMode BackpressureMode
	outputFn         func(kcpFrame []byte)
	scratch          []byte
}

// NewKCPSession initializes a tuned low-latency KCP state machine.
// maxPayload is clamped to MaxOverlayPayload - E2EETagSize (1164 bytes) so that
// 20B Overlay + 16B E2EE Tag + 24B KCP Header + 1140B Data <= 1200B physical MTU.
func NewKCPSession(conv uint32, outputFn func(kcpFrame []byte)) *KCPSession {
	mtu := MaxOverlayPayload - E2EETagSize // 1164 bytes max KCP packet
	mss := mtu - KCPHeaderSize             // 1140 bytes max user data per segment
	return &KCPSession{
		conv:       conv,
		mtu:        mtu,
		mss:        mss,
		sndWnd:     IKCP_WND_SND,
		rcvWnd:     IKCP_WND_RCV,
		rmtWnd:     IKCP_WND_RCV,
		rxRto:      IKCP_RTO_DEF,
		rxMinrto:   IKCP_RTO_NDL,
		interval:   10,
		nodelay:    true,
		fastResend: 2,
		nocwnd:     true,
		outputFn:   outputFn,
		scratch:    make([]byte, mtu),
	}
}

// SetBackpressure updates the 3-level SCTP backpressure valve based on bufferedAmount bytes.
func (k *KCPSession) SetBackpressure(bufferedBytes int) BackpressureMode {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case bufferedBytes <= BackpressureLowWater:
		k.backpressureMode = BackpressureTurbo
	case bufferedBytes <= BackpressureMidWater:
		k.backpressureMode = BackpressureMild
	default:
		k.backpressureMode = BackpressureCircuit
	}
	return k.backpressureMode
}

// Backpressure returns the current backpressure mode.
func (k *KCPSession) Backpressure() BackpressureMode {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.backpressureMode
}

// Send splits payload into <= 1140-byte MSS fragments and queues them for transmission.
func (k *KCPSession) Send(payload []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.backpressureMode == BackpressureCircuit {
		return ErrBackpressureCircuitOpen
	}
	if len(payload) == 0 {
		return nil
	}

	count := 1
	if len(payload) > k.mss {
		count = (len(payload) + k.mss - 1) / k.mss
	}
	if count > 255 {
		return errors.New("kcp: message too large for fragment counter (>255 segments)")
	}

	offset := 0
	for i := 0; i < count; i++ {
		size := len(payload) - offset
		if size > k.mss {
			size = k.mss
		}
		segData := make([]byte, size)
		copy(segData, payload[offset:offset+size])
		seg := kcpSegment{
			conv: k.conv,
			cmd:  IKCP_CMD_PUSH,
			frg:  uint8(count - i - 1),
			data: segData,
		}
		k.sndQueue = append(k.sndQueue, seg)
		offset += size
	}
	return nil
}

// Recv extracts the next complete reassembled message from rcvQueue, or returns nil if none ready.
func (k *KCPSession) Recv() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()

	if len(k.rcvQueue) == 0 {
		return nil
	}
	// Check if all fragments of the next message have arrived
	peekSize := -1
	for i, seg := range k.rcvQueue {
		if seg.frg == 0 {
			peekSize = i + 1
			break
		}
	}
	if peekSize < 0 {
		return nil
	}

	var totalLen int
	for i := 0; i < peekSize; i++ {
		totalLen += len(k.rcvQueue[i].data)
	}
	out := make([]byte, 0, totalLen)
	for i := 0; i < peekSize; i++ {
		out = append(out, k.rcvQueue[i].data...)
	}
	k.rcvQueue = k.rcvQueue[peekSize:]
	k.moveRcvBufToQueueLocked()
	return out
}

// Input feeds a decrypted KCP frame received from the network and triggers an event-driven flush.
func (k *KCPSession) Input(data []byte, nowMillis uint32) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if len(data) < KCPHeaderSize {
		return ErrInvalidKCPSegment
	}
	k.current = nowMillis
	var maxAck uint32
	var hasAck bool

	offset := 0
	for len(data)-offset >= KCPHeaderSize {
		hdr := data[offset : offset+KCPHeaderSize]
		conv := binary.LittleEndian.Uint32(hdr[0:4])
		if conv != k.conv {
			return ErrInvalidKCPSegment
		}
		cmd := hdr[4]
		frg := hdr[5]
		wnd := binary.LittleEndian.Uint16(hdr[6:8])
		ts := binary.LittleEndian.Uint32(hdr[8:12])
		sn := binary.LittleEndian.Uint32(hdr[12:16])
		una := binary.LittleEndian.Uint32(hdr[16:20])
		length := int(binary.LittleEndian.Uint32(hdr[20:24]))
		offset += KCPHeaderSize

		if len(data)-offset < length || length < 0 {
			return ErrInvalidKCPSegment
		}
		payload := data[offset : offset+length]
		offset += length

		k.rmtWnd = wnd
		k.parseUnaLocked(una)
		k.shrinkBufLocked()

		switch cmd {
		case IKCP_CMD_ACK:
			if int32(k.current-ts) >= 0 {
				k.updateAckLocked(int32(k.current - ts))
			}
			k.parseAckLocked(sn)
			k.shrinkBufLocked()
			if !hasAck || int32(sn-maxAck) > 0 {
				maxAck = sn
				hasAck = true
			}
		case IKCP_CMD_PUSH:
			if int32(sn-(k.rcvNxt+uint32(k.rcvWnd))) < 0 {
				k.acklist = append(k.acklist, [2]uint32{sn, ts})
				if int32(sn-k.rcvNxt) >= 0 {
					dup := false
					idx := len(k.rcvBuf)
					for i := len(k.rcvBuf) - 1; i >= 0; i-- {
						if k.rcvBuf[i].sn == sn {
							dup = true
							break
						}
						if int32(sn-k.rcvBuf[i].sn) > 0 {
							idx = i + 1
							break
						}
						idx = i
					}
					if !dup {
						cp := make([]byte, len(payload))
						copy(cp, payload)
						seg := kcpSegment{
							conv: conv, cmd: cmd, frg: frg, wnd: wnd,
							ts: ts, sn: sn, una: una, data: cp,
						}
						k.rcvBuf = append(k.rcvBuf, kcpSegment{})
						copy(k.rcvBuf[idx+1:], k.rcvBuf[idx:])
						k.rcvBuf[idx] = seg
					}
				}
				k.moveRcvBufToQueueLocked()
			}
		case IKCP_CMD_WASK, IKCP_CMD_WINS:
			// Window probes handled by wnd advertisement
		default:
			return ErrInvalidKCPSegment
		}
	}

	if hasAck && k.backpressureMode == BackpressureTurbo {
		for i := range k.sndBuf {
			if int32(maxAck-k.sndBuf[i].sn) > 0 {
				k.sndBuf[i].fastack++
			}
		}
	}

	// Event-driven hybrid flush: immediately flush ACKs and pending segments on packet arrival
	if k.backpressureMode != BackpressureCircuit {
		k.flushLocked()
	}
	return nil
}

// Update advances the KCP timer and flushes segments when due.
func (k *KCPSession) Update(nowMillis uint32) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.current = nowMillis
	if !k.updated {
		k.updated = true
		k.tsFlush = k.current
	}
	// If SCTP backpressure valve is in Circuit-Breaker mode (>64KB), suspend retransmissions!
	if k.backpressureMode == BackpressureCircuit {
		return
	}

	slap := int32(k.current - k.tsFlush)
	if slap >= 10000 || slap < -10000 {
		k.tsFlush = k.current
		slap = 0
	}
	if slap >= 0 {
		k.tsFlush += k.interval
		if int32(k.current-k.tsFlush) >= 0 {
			k.tsFlush = k.current + k.interval
		}
		k.flushLocked()
	}
}

// Flush immediately flushes pending send queue and ACKs.
func (k *KCPSession) Flush(nowMillis uint32) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.current = nowMillis
	if k.backpressureMode != BackpressureCircuit {
		k.flushLocked()
	}
}

func (k *KCPSession) flushLocked() {
	wnd := k.unusedWndLocked()
	current := k.current

	offset := 0
	flushScratch := func() {
		if offset > 0 && k.outputFn != nil {
			out := make([]byte, offset)
			copy(out, k.scratch[:offset])
			k.outputFn(out)
			offset = 0
		}
	}

	// 1. Flush ACK list
	for _, ack := range k.acklist {
		if offset+KCPHeaderSize > k.mtu {
			flushScratch()
		}
		seg := kcpSegment{
			conv: k.conv,
			cmd:  IKCP_CMD_ACK,
			wnd:  wnd,
			una:  k.rcvNxt,
			sn:   ack[0],
			ts:   ack[1],
		}
		seg.encodeHeader(k.scratch[offset : offset+KCPHeaderSize])
		offset += KCPHeaderSize
	}
	k.acklist = k.acklist[:0]

	// 2. Move segments from sndQueue to sndBuf within congestion/send window
	cwnd := k.sndWnd
	if k.rmtWnd < cwnd {
		cwnd = k.rmtWnd
	}
	for int32(k.sndNxt-(k.sndUna+uint32(cwnd))) < 0 && len(k.sndQueue) > 0 {
		newseg := k.sndQueue[0]
		k.sndQueue = k.sndQueue[1:]
		newseg.conv = k.conv
		newseg.cmd = IKCP_CMD_PUSH
		newseg.wnd = wnd
		newseg.ts = current
		newseg.sn = k.sndNxt
		k.sndNxt++
		newseg.una = k.rcvNxt
		newseg.resendts = current
		newseg.rto = k.rxRto
		newseg.fastack = 0
		newseg.xmit = 0
		k.sndBuf = append(k.sndBuf, newseg)
	}

	// 3. Determine RTO multiplier based on Backpressure Valve
	rtoScaleNum := uint32(1)
	rtoScaleDen := uint32(1)
	allowFastResend := k.fastResend > 0
	if k.backpressureMode == BackpressureMild {
		// Mild backpressure (0 < bufferedAmount <= 64KB): scale RTO by 1.5x and disable fast retransmit
		rtoScaleNum = 3
		rtoScaleDen = 2
		allowFastResend = false
	}

	// 4. Flush data segments (first send, RTO retransmit, or Fast Retransmit)
	for i := range k.sndBuf {
		segment := &k.sndBuf[i]
		needSend := false
		if segment.xmit == 0 {
			needSend = true
			segment.xmit++
			segment.rto = (k.rxRto * rtoScaleNum) / rtoScaleDen
			segment.resendts = current + segment.rto
		} else if int32(current-segment.resendts) >= 0 {
			needSend = true
			segment.xmit++
			if !k.nodelay {
				segment.rto += k.rxRto
			} else {
				step := (k.rxRto * rtoScaleNum) / rtoScaleDen
				segment.rto += step / 2
			}
			if segment.rto > IKCP_RTO_MAX {
				segment.rto = IKCP_RTO_MAX
			}
			segment.resendts = current + segment.rto
		} else if allowFastResend && segment.fastack >= k.fastResend {
			needSend = true
			segment.xmit++
			segment.fastack = 0
			segment.resendts = current + segment.rto
		}

		if needSend {
			segment.ts = current
			segment.wnd = wnd
			segment.una = k.rcvNxt

			need := KCPHeaderSize + len(segment.data)
			if offset+need > k.mtu {
				flushScratch()
			}
			segment.encodeHeader(k.scratch[offset : offset+KCPHeaderSize])
			copy(k.scratch[offset+KCPHeaderSize:offset+need], segment.data)
			offset += need
		}
	}

	flushScratch()
}

func (k *KCPSession) unusedWndLocked() uint16 {
	if len(k.rcvQueue) < int(k.rcvWnd) {
		return k.rcvWnd - uint16(len(k.rcvQueue))
	}
	return 0
}

func (k *KCPSession) moveRcvBufToQueueLocked() {
	for len(k.rcvBuf) > 0 {
		seg := k.rcvBuf[0]
		if seg.sn == k.rcvNxt && len(k.rcvQueue) < int(k.rcvWnd) {
			k.rcvBuf = k.rcvBuf[1:]
			k.rcvQueue = append(k.rcvQueue, seg)
			k.rcvNxt++
		} else {
			break
		}
	}
}

func (k *KCPSession) parseUnaLocked(una uint32) {
	idx := 0
	for idx < len(k.sndBuf) {
		if int32(una-k.sndBuf[idx].sn) > 0 {
			idx++
		} else {
			break
		}
	}
	if idx > 0 {
		k.sndBuf = k.sndBuf[idx:]
	}
}

func (k *KCPSession) parseAckLocked(sn uint32) {
	if int32(sn-k.sndUna) < 0 || int32(sn-k.sndNxt) >= 0 {
		return
	}
	for i := range k.sndBuf {
		if sn == k.sndBuf[i].sn {
			k.sndBuf = append(k.sndBuf[:i], k.sndBuf[i+1:]...)
			break
		}
		if int32(sn-k.sndBuf[i].sn) < 0 {
			break
		}
	}
}

func (k *KCPSession) shrinkBufLocked() {
	if len(k.sndBuf) > 0 {
		k.sndUna = k.sndBuf[0].sn
	} else {
		k.sndUna = k.sndNxt
	}
}

func (k *KCPSession) updateAckLocked(rtt int32) {
	if k.rxSrtt == 0 {
		k.rxSrtt = rtt
		k.rxRttval = rtt / 2
	} else {
		delta := rtt - k.rxSrtt
		if delta < 0 {
			delta = -delta
		}
		k.rxRttval = (3*k.rxRttval + delta) / 4
		k.rxSrtt = (7*k.rxSrtt + rtt) / 8
		if k.rxSrtt < 1 {
			k.rxSrtt = 1
		}
	}
	rto := k.rxSrtt + maxInt32(int32(k.interval), 4*k.rxRttval)
	if uint32(rto) < k.rxMinrto {
		k.rxRto = k.rxMinrto
	} else if uint32(rto) > IKCP_RTO_MAX {
		k.rxRto = IKCP_RTO_MAX
	} else {
		k.rxRto = uint32(rto)
	}
}

func maxInt32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
