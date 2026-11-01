//go:build !with_low_memory

package vmess

const muxPacketQueueSize = 4
const muxSessionQueuedPackets = 16
