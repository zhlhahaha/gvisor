// automatically generated by stateify.

package fuse

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (conn *connection) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.connection"
}

func (conn *connection) StateFields() []string {
	return []string{
		"fd",
		"attributeVersion",
		"initialized",
		"initializedChan",
		"connected",
		"connInitError",
		"connInitSuccess",
		"aborted",
		"numWaiting",
		"asyncNum",
		"asyncCongestionThreshold",
		"asyncNumMax",
		"maxRead",
		"maxWrite",
		"maxPages",
		"minor",
		"atomicOTrunc",
		"asyncRead",
		"writebackCache",
		"bigWrites",
		"dontMask",
		"noOpen",
	}
}

func (conn *connection) beforeSave() {}

func (conn *connection) StateSave(stateSinkObject state.Sink) {
	conn.beforeSave()
	var initializedChanValue bool = conn.saveInitializedChan()
	stateSinkObject.SaveValue(3, initializedChanValue)
	stateSinkObject.Save(0, &conn.fd)
	stateSinkObject.Save(1, &conn.attributeVersion)
	stateSinkObject.Save(2, &conn.initialized)
	stateSinkObject.Save(4, &conn.connected)
	stateSinkObject.Save(5, &conn.connInitError)
	stateSinkObject.Save(6, &conn.connInitSuccess)
	stateSinkObject.Save(7, &conn.aborted)
	stateSinkObject.Save(8, &conn.numWaiting)
	stateSinkObject.Save(9, &conn.asyncNum)
	stateSinkObject.Save(10, &conn.asyncCongestionThreshold)
	stateSinkObject.Save(11, &conn.asyncNumMax)
	stateSinkObject.Save(12, &conn.maxRead)
	stateSinkObject.Save(13, &conn.maxWrite)
	stateSinkObject.Save(14, &conn.maxPages)
	stateSinkObject.Save(15, &conn.minor)
	stateSinkObject.Save(16, &conn.atomicOTrunc)
	stateSinkObject.Save(17, &conn.asyncRead)
	stateSinkObject.Save(18, &conn.writebackCache)
	stateSinkObject.Save(19, &conn.bigWrites)
	stateSinkObject.Save(20, &conn.dontMask)
	stateSinkObject.Save(21, &conn.noOpen)
}

func (conn *connection) afterLoad() {}

func (conn *connection) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &conn.fd)
	stateSourceObject.Load(1, &conn.attributeVersion)
	stateSourceObject.Load(2, &conn.initialized)
	stateSourceObject.Load(4, &conn.connected)
	stateSourceObject.Load(5, &conn.connInitError)
	stateSourceObject.Load(6, &conn.connInitSuccess)
	stateSourceObject.Load(7, &conn.aborted)
	stateSourceObject.Load(8, &conn.numWaiting)
	stateSourceObject.Load(9, &conn.asyncNum)
	stateSourceObject.Load(10, &conn.asyncCongestionThreshold)
	stateSourceObject.Load(11, &conn.asyncNumMax)
	stateSourceObject.Load(12, &conn.maxRead)
	stateSourceObject.Load(13, &conn.maxWrite)
	stateSourceObject.Load(14, &conn.maxPages)
	stateSourceObject.Load(15, &conn.minor)
	stateSourceObject.Load(16, &conn.atomicOTrunc)
	stateSourceObject.Load(17, &conn.asyncRead)
	stateSourceObject.Load(18, &conn.writebackCache)
	stateSourceObject.Load(19, &conn.bigWrites)
	stateSourceObject.Load(20, &conn.dontMask)
	stateSourceObject.Load(21, &conn.noOpen)
	stateSourceObject.LoadValue(3, new(bool), func(y interface{}) { conn.loadInitializedChan(y.(bool)) })
}

func (f *fuseDevice) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.fuseDevice"
}

func (f *fuseDevice) StateFields() []string {
	return []string{}
}

func (f *fuseDevice) beforeSave() {}

func (f *fuseDevice) StateSave(stateSinkObject state.Sink) {
	f.beforeSave()
}

func (f *fuseDevice) afterLoad() {}

func (f *fuseDevice) StateLoad(stateSourceObject state.Source) {
}

func (fd *DeviceFD) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.DeviceFD"
}

func (fd *DeviceFD) StateFields() []string {
	return []string{
		"vfsfd",
		"FileDescriptionDefaultImpl",
		"DentryMetadataFileDescriptionImpl",
		"NoLockFD",
		"nextOpID",
		"queue",
		"numActiveRequests",
		"completions",
		"writeCursor",
		"writeBuf",
		"writeCursorFR",
		"waitQueue",
		"fullQueueCh",
		"fs",
	}
}

func (fd *DeviceFD) beforeSave() {}

func (fd *DeviceFD) StateSave(stateSinkObject state.Sink) {
	fd.beforeSave()
	var fullQueueChValue int = fd.saveFullQueueCh()
	stateSinkObject.SaveValue(12, fullQueueChValue)
	stateSinkObject.Save(0, &fd.vfsfd)
	stateSinkObject.Save(1, &fd.FileDescriptionDefaultImpl)
	stateSinkObject.Save(2, &fd.DentryMetadataFileDescriptionImpl)
	stateSinkObject.Save(3, &fd.NoLockFD)
	stateSinkObject.Save(4, &fd.nextOpID)
	stateSinkObject.Save(5, &fd.queue)
	stateSinkObject.Save(6, &fd.numActiveRequests)
	stateSinkObject.Save(7, &fd.completions)
	stateSinkObject.Save(8, &fd.writeCursor)
	stateSinkObject.Save(9, &fd.writeBuf)
	stateSinkObject.Save(10, &fd.writeCursorFR)
	stateSinkObject.Save(11, &fd.waitQueue)
	stateSinkObject.Save(13, &fd.fs)
}

func (fd *DeviceFD) afterLoad() {}

func (fd *DeviceFD) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fd.vfsfd)
	stateSourceObject.Load(1, &fd.FileDescriptionDefaultImpl)
	stateSourceObject.Load(2, &fd.DentryMetadataFileDescriptionImpl)
	stateSourceObject.Load(3, &fd.NoLockFD)
	stateSourceObject.Load(4, &fd.nextOpID)
	stateSourceObject.Load(5, &fd.queue)
	stateSourceObject.Load(6, &fd.numActiveRequests)
	stateSourceObject.Load(7, &fd.completions)
	stateSourceObject.Load(8, &fd.writeCursor)
	stateSourceObject.Load(9, &fd.writeBuf)
	stateSourceObject.Load(10, &fd.writeCursorFR)
	stateSourceObject.Load(11, &fd.waitQueue)
	stateSourceObject.Load(13, &fd.fs)
	stateSourceObject.LoadValue(12, new(int), func(y interface{}) { fd.loadFullQueueCh(y.(int)) })
}

func (fsType *FilesystemType) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.FilesystemType"
}

func (fsType *FilesystemType) StateFields() []string {
	return []string{}
}

func (fsType *FilesystemType) beforeSave() {}

func (fsType *FilesystemType) StateSave(stateSinkObject state.Sink) {
	fsType.beforeSave()
}

func (fsType *FilesystemType) afterLoad() {}

func (fsType *FilesystemType) StateLoad(stateSourceObject state.Source) {
}

func (f *filesystemOptions) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.filesystemOptions"
}

func (f *filesystemOptions) StateFields() []string {
	return []string{
		"userID",
		"groupID",
		"rootMode",
		"maxActiveRequests",
		"maxRead",
	}
}

func (f *filesystemOptions) beforeSave() {}

func (f *filesystemOptions) StateSave(stateSinkObject state.Sink) {
	f.beforeSave()
	stateSinkObject.Save(0, &f.userID)
	stateSinkObject.Save(1, &f.groupID)
	stateSinkObject.Save(2, &f.rootMode)
	stateSinkObject.Save(3, &f.maxActiveRequests)
	stateSinkObject.Save(4, &f.maxRead)
}

func (f *filesystemOptions) afterLoad() {}

func (f *filesystemOptions) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &f.userID)
	stateSourceObject.Load(1, &f.groupID)
	stateSourceObject.Load(2, &f.rootMode)
	stateSourceObject.Load(3, &f.maxActiveRequests)
	stateSourceObject.Load(4, &f.maxRead)
}

func (fs *filesystem) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.filesystem"
}

func (fs *filesystem) StateFields() []string {
	return []string{
		"Filesystem",
		"devMinor",
		"conn",
		"opts",
		"umounted",
	}
}

func (fs *filesystem) beforeSave() {}

func (fs *filesystem) StateSave(stateSinkObject state.Sink) {
	fs.beforeSave()
	stateSinkObject.Save(0, &fs.Filesystem)
	stateSinkObject.Save(1, &fs.devMinor)
	stateSinkObject.Save(2, &fs.conn)
	stateSinkObject.Save(3, &fs.opts)
	stateSinkObject.Save(4, &fs.umounted)
}

func (fs *filesystem) afterLoad() {}

func (fs *filesystem) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fs.Filesystem)
	stateSourceObject.Load(1, &fs.devMinor)
	stateSourceObject.Load(2, &fs.conn)
	stateSourceObject.Load(3, &fs.opts)
	stateSourceObject.Load(4, &fs.umounted)
}

func (i *inode) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.inode"
}

func (i *inode) StateFields() []string {
	return []string{
		"inodeRefs",
		"InodeAlwaysValid",
		"InodeAttrs",
		"InodeDirectoryNoNewChildren",
		"InodeNotSymlink",
		"OrderedChildren",
		"fs",
		"metadataMu",
		"nodeID",
		"locks",
		"size",
		"attributeVersion",
		"attributeTime",
		"version",
		"link",
	}
}

func (i *inode) beforeSave() {}

func (i *inode) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
	stateSinkObject.Save(0, &i.inodeRefs)
	stateSinkObject.Save(1, &i.InodeAlwaysValid)
	stateSinkObject.Save(2, &i.InodeAttrs)
	stateSinkObject.Save(3, &i.InodeDirectoryNoNewChildren)
	stateSinkObject.Save(4, &i.InodeNotSymlink)
	stateSinkObject.Save(5, &i.OrderedChildren)
	stateSinkObject.Save(6, &i.fs)
	stateSinkObject.Save(7, &i.metadataMu)
	stateSinkObject.Save(8, &i.nodeID)
	stateSinkObject.Save(9, &i.locks)
	stateSinkObject.Save(10, &i.size)
	stateSinkObject.Save(11, &i.attributeVersion)
	stateSinkObject.Save(12, &i.attributeTime)
	stateSinkObject.Save(13, &i.version)
	stateSinkObject.Save(14, &i.link)
}

func (i *inode) afterLoad() {}

func (i *inode) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &i.inodeRefs)
	stateSourceObject.Load(1, &i.InodeAlwaysValid)
	stateSourceObject.Load(2, &i.InodeAttrs)
	stateSourceObject.Load(3, &i.InodeDirectoryNoNewChildren)
	stateSourceObject.Load(4, &i.InodeNotSymlink)
	stateSourceObject.Load(5, &i.OrderedChildren)
	stateSourceObject.Load(6, &i.fs)
	stateSourceObject.Load(7, &i.metadataMu)
	stateSourceObject.Load(8, &i.nodeID)
	stateSourceObject.Load(9, &i.locks)
	stateSourceObject.Load(10, &i.size)
	stateSourceObject.Load(11, &i.attributeVersion)
	stateSourceObject.Load(12, &i.attributeTime)
	stateSourceObject.Load(13, &i.version)
	stateSourceObject.Load(14, &i.link)
}

func (r *inodeRefs) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.inodeRefs"
}

func (r *inodeRefs) StateFields() []string {
	return []string{
		"refCount",
	}
}

func (r *inodeRefs) beforeSave() {}

func (r *inodeRefs) StateSave(stateSinkObject state.Sink) {
	r.beforeSave()
	stateSinkObject.Save(0, &r.refCount)
}

func (r *inodeRefs) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &r.refCount)
	stateSourceObject.AfterLoad(r.afterLoad)
}

func (l *requestList) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.requestList"
}

func (l *requestList) StateFields() []string {
	return []string{
		"head",
		"tail",
	}
}

func (l *requestList) beforeSave() {}

func (l *requestList) StateSave(stateSinkObject state.Sink) {
	l.beforeSave()
	stateSinkObject.Save(0, &l.head)
	stateSinkObject.Save(1, &l.tail)
}

func (l *requestList) afterLoad() {}

func (l *requestList) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &l.head)
	stateSourceObject.Load(1, &l.tail)
}

func (e *requestEntry) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.requestEntry"
}

func (e *requestEntry) StateFields() []string {
	return []string{
		"next",
		"prev",
	}
}

func (e *requestEntry) beforeSave() {}

func (e *requestEntry) StateSave(stateSinkObject state.Sink) {
	e.beforeSave()
	stateSinkObject.Save(0, &e.next)
	stateSinkObject.Save(1, &e.prev)
}

func (e *requestEntry) afterLoad() {}

func (e *requestEntry) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &e.next)
	stateSourceObject.Load(1, &e.prev)
}

func (r *Request) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.Request"
}

func (r *Request) StateFields() []string {
	return []string{
		"requestEntry",
		"id",
		"hdr",
		"data",
		"payload",
		"async",
		"noReply",
	}
}

func (r *Request) beforeSave() {}

func (r *Request) StateSave(stateSinkObject state.Sink) {
	r.beforeSave()
	stateSinkObject.Save(0, &r.requestEntry)
	stateSinkObject.Save(1, &r.id)
	stateSinkObject.Save(2, &r.hdr)
	stateSinkObject.Save(3, &r.data)
	stateSinkObject.Save(4, &r.payload)
	stateSinkObject.Save(5, &r.async)
	stateSinkObject.Save(6, &r.noReply)
}

func (r *Request) afterLoad() {}

func (r *Request) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &r.requestEntry)
	stateSourceObject.Load(1, &r.id)
	stateSourceObject.Load(2, &r.hdr)
	stateSourceObject.Load(3, &r.data)
	stateSourceObject.Load(4, &r.payload)
	stateSourceObject.Load(5, &r.async)
	stateSourceObject.Load(6, &r.noReply)
}

func (f *futureResponse) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.futureResponse"
}

func (f *futureResponse) StateFields() []string {
	return []string{
		"opcode",
		"ch",
		"hdr",
		"data",
		"async",
	}
}

func (f *futureResponse) beforeSave() {}

func (f *futureResponse) StateSave(stateSinkObject state.Sink) {
	f.beforeSave()
	stateSinkObject.Save(0, &f.opcode)
	stateSinkObject.Save(1, &f.ch)
	stateSinkObject.Save(2, &f.hdr)
	stateSinkObject.Save(3, &f.data)
	stateSinkObject.Save(4, &f.async)
}

func (f *futureResponse) afterLoad() {}

func (f *futureResponse) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &f.opcode)
	stateSourceObject.Load(1, &f.ch)
	stateSourceObject.Load(2, &f.hdr)
	stateSourceObject.Load(3, &f.data)
	stateSourceObject.Load(4, &f.async)
}

func (r *Response) StateTypeName() string {
	return "pkg/sentry/fsimpl/fuse.Response"
}

func (r *Response) StateFields() []string {
	return []string{
		"opcode",
		"hdr",
		"data",
	}
}

func (r *Response) beforeSave() {}

func (r *Response) StateSave(stateSinkObject state.Sink) {
	r.beforeSave()
	stateSinkObject.Save(0, &r.opcode)
	stateSinkObject.Save(1, &r.hdr)
	stateSinkObject.Save(2, &r.data)
}

func (r *Response) afterLoad() {}

func (r *Response) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &r.opcode)
	stateSourceObject.Load(1, &r.hdr)
	stateSourceObject.Load(2, &r.data)
}

func init() {
	state.Register((*connection)(nil))
	state.Register((*fuseDevice)(nil))
	state.Register((*DeviceFD)(nil))
	state.Register((*FilesystemType)(nil))
	state.Register((*filesystemOptions)(nil))
	state.Register((*filesystem)(nil))
	state.Register((*inode)(nil))
	state.Register((*inodeRefs)(nil))
	state.Register((*requestList)(nil))
	state.Register((*requestEntry)(nil))
	state.Register((*Request)(nil))
	state.Register((*futureResponse)(nil))
	state.Register((*Response)(nil))
}
