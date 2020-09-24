// automatically generated by stateify.

package raw

import (
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

func (x *rawPacket) StateTypeName() string {
	return "pkg/tcpip/transport/raw.rawPacket"
}

func (x *rawPacket) StateFields() []string {
	return []string{
		"rawPacketEntry",
		"data",
		"timestampNS",
		"senderAddr",
	}
}

func (x *rawPacket) beforeSave() {}

func (x *rawPacket) StateSave(m state.Sink) {
	x.beforeSave()
	var data buffer.VectorisedView = x.saveData()
	m.SaveValue(1, data)
	m.Save(0, &x.rawPacketEntry)
	m.Save(2, &x.timestampNS)
	m.Save(3, &x.senderAddr)
}

func (x *rawPacket) afterLoad() {}

func (x *rawPacket) StateLoad(m state.Source) {
	m.Load(0, &x.rawPacketEntry)
	m.Load(2, &x.timestampNS)
	m.Load(3, &x.senderAddr)
	m.LoadValue(1, new(buffer.VectorisedView), func(y interface{}) { x.loadData(y.(buffer.VectorisedView)) })
}

func (x *endpoint) StateTypeName() string {
	return "pkg/tcpip/transport/raw.endpoint"
}

func (x *endpoint) StateFields() []string {
	return []string{
		"TransportEndpointInfo",
		"waiterQueue",
		"associated",
		"hdrIncluded",
		"rcvList",
		"rcvBufSize",
		"rcvBufSizeMax",
		"rcvClosed",
		"sndBufSize",
		"sndBufSizeMax",
		"closed",
		"connected",
		"bound",
		"linger",
		"owner",
	}
}

func (x *endpoint) StateSave(m state.Sink) {
	x.beforeSave()
	var rcvBufSizeMax int = x.saveRcvBufSizeMax()
	m.SaveValue(6, rcvBufSizeMax)
	m.Save(0, &x.TransportEndpointInfo)
	m.Save(1, &x.waiterQueue)
	m.Save(2, &x.associated)
	m.Save(3, &x.hdrIncluded)
	m.Save(4, &x.rcvList)
	m.Save(5, &x.rcvBufSize)
	m.Save(7, &x.rcvClosed)
	m.Save(8, &x.sndBufSize)
	m.Save(9, &x.sndBufSizeMax)
	m.Save(10, &x.closed)
	m.Save(11, &x.connected)
	m.Save(12, &x.bound)
	m.Save(13, &x.linger)
	m.Save(14, &x.owner)
}

func (x *endpoint) StateLoad(m state.Source) {
	m.Load(0, &x.TransportEndpointInfo)
	m.Load(1, &x.waiterQueue)
	m.Load(2, &x.associated)
	m.Load(3, &x.hdrIncluded)
	m.Load(4, &x.rcvList)
	m.Load(5, &x.rcvBufSize)
	m.Load(7, &x.rcvClosed)
	m.Load(8, &x.sndBufSize)
	m.Load(9, &x.sndBufSizeMax)
	m.Load(10, &x.closed)
	m.Load(11, &x.connected)
	m.Load(12, &x.bound)
	m.Load(13, &x.linger)
	m.Load(14, &x.owner)
	m.LoadValue(6, new(int), func(y interface{}) { x.loadRcvBufSizeMax(y.(int)) })
	m.AfterLoad(x.afterLoad)
}

func (x *rawPacketList) StateTypeName() string {
	return "pkg/tcpip/transport/raw.rawPacketList"
}

func (x *rawPacketList) StateFields() []string {
	return []string{
		"head",
		"tail",
	}
}

func (x *rawPacketList) beforeSave() {}

func (x *rawPacketList) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.head)
	m.Save(1, &x.tail)
}

func (x *rawPacketList) afterLoad() {}

func (x *rawPacketList) StateLoad(m state.Source) {
	m.Load(0, &x.head)
	m.Load(1, &x.tail)
}

func (x *rawPacketEntry) StateTypeName() string {
	return "pkg/tcpip/transport/raw.rawPacketEntry"
}

func (x *rawPacketEntry) StateFields() []string {
	return []string{
		"next",
		"prev",
	}
}

func (x *rawPacketEntry) beforeSave() {}

func (x *rawPacketEntry) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.next)
	m.Save(1, &x.prev)
}

func (x *rawPacketEntry) afterLoad() {}

func (x *rawPacketEntry) StateLoad(m state.Source) {
	m.Load(0, &x.next)
	m.Load(1, &x.prev)
}

func init() {
	state.Register((*rawPacket)(nil))
	state.Register((*endpoint)(nil))
	state.Register((*rawPacketList)(nil))
	state.Register((*rawPacketEntry)(nil))
}
