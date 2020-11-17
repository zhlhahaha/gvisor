// Automatically generated marshal implementation. See tools/go_marshal.

package linux

import (
    "gvisor.dev/gvisor/pkg/gohacks"
    "gvisor.dev/gvisor/pkg/marshal"
    "gvisor.dev/gvisor/pkg/safecopy"
    "gvisor.dev/gvisor/pkg/usermem"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

// Marshallable types used by this file.
var _ marshal.Marshallable = (*BPFInstruction)(nil)
var _ marshal.Marshallable = (*CapUserData)(nil)
var _ marshal.Marshallable = (*CapUserHeader)(nil)
var _ marshal.Marshallable = (*ClockT)(nil)
var _ marshal.Marshallable = (*ControlMessageCredentials)(nil)
var _ marshal.Marshallable = (*DigestMetadata)(nil)
var _ marshal.Marshallable = (*ExtensionName)(nil)
var _ marshal.Marshallable = (*FOwnerEx)(nil)
var _ marshal.Marshallable = (*FUSEAttr)(nil)
var _ marshal.Marshallable = (*FUSECreateMeta)(nil)
var _ marshal.Marshallable = (*FUSEDirentMeta)(nil)
var _ marshal.Marshallable = (*FUSEEntryOut)(nil)
var _ marshal.Marshallable = (*FUSEGetAttrIn)(nil)
var _ marshal.Marshallable = (*FUSEGetAttrOut)(nil)
var _ marshal.Marshallable = (*FUSEHeaderIn)(nil)
var _ marshal.Marshallable = (*FUSEHeaderOut)(nil)
var _ marshal.Marshallable = (*FUSEInitIn)(nil)
var _ marshal.Marshallable = (*FUSEInitOut)(nil)
var _ marshal.Marshallable = (*FUSEMkdirMeta)(nil)
var _ marshal.Marshallable = (*FUSEMknodMeta)(nil)
var _ marshal.Marshallable = (*FUSEOpID)(nil)
var _ marshal.Marshallable = (*FUSEOpcode)(nil)
var _ marshal.Marshallable = (*FUSEOpenIn)(nil)
var _ marshal.Marshallable = (*FUSEOpenOut)(nil)
var _ marshal.Marshallable = (*FUSEReadIn)(nil)
var _ marshal.Marshallable = (*FUSEReleaseIn)(nil)
var _ marshal.Marshallable = (*FUSESetAttrIn)(nil)
var _ marshal.Marshallable = (*FUSEWriteIn)(nil)
var _ marshal.Marshallable = (*FUSEWriteOut)(nil)
var _ marshal.Marshallable = (*Flock)(nil)
var _ marshal.Marshallable = (*IFConf)(nil)
var _ marshal.Marshallable = (*IFReq)(nil)
var _ marshal.Marshallable = (*IOCallback)(nil)
var _ marshal.Marshallable = (*IOEvent)(nil)
var _ marshal.Marshallable = (*IP6TEntry)(nil)
var _ marshal.Marshallable = (*IP6TIP)(nil)
var _ marshal.Marshallable = (*IP6TReplace)(nil)
var _ marshal.Marshallable = (*IPCPerm)(nil)
var _ marshal.Marshallable = (*IPTEntry)(nil)
var _ marshal.Marshallable = (*IPTGetEntries)(nil)
var _ marshal.Marshallable = (*IPTGetinfo)(nil)
var _ marshal.Marshallable = (*IPTIP)(nil)
var _ marshal.Marshallable = (*Inet6Addr)(nil)
var _ marshal.Marshallable = (*InetAddr)(nil)
var _ marshal.Marshallable = (*ItimerVal)(nil)
var _ marshal.Marshallable = (*Itimerspec)(nil)
var _ marshal.Marshallable = (*Linger)(nil)
var _ marshal.Marshallable = (*NumaPolicy)(nil)
var _ marshal.Marshallable = (*PollFD)(nil)
var _ marshal.Marshallable = (*RSeqCriticalSection)(nil)
var _ marshal.Marshallable = (*RobustListHead)(nil)
var _ marshal.Marshallable = (*Rusage)(nil)
var _ marshal.Marshallable = (*SeccompData)(nil)
var _ marshal.Marshallable = (*Sembuf)(nil)
var _ marshal.Marshallable = (*ShmInfo)(nil)
var _ marshal.Marshallable = (*ShmParams)(nil)
var _ marshal.Marshallable = (*ShmidDS)(nil)
var _ marshal.Marshallable = (*Sigevent)(nil)
var _ marshal.Marshallable = (*SignalSet)(nil)
var _ marshal.Marshallable = (*SignalfdSiginfo)(nil)
var _ marshal.Marshallable = (*SockAddrInet)(nil)
var _ marshal.Marshallable = (*SockAddrInet6)(nil)
var _ marshal.Marshallable = (*SockAddrLink)(nil)
var _ marshal.Marshallable = (*SockAddrNetlink)(nil)
var _ marshal.Marshallable = (*SockAddrUnix)(nil)
var _ marshal.Marshallable = (*Statfs)(nil)
var _ marshal.Marshallable = (*Statx)(nil)
var _ marshal.Marshallable = (*StatxTimestamp)(nil)
var _ marshal.Marshallable = (*Sysinfo)(nil)
var _ marshal.Marshallable = (*TCPInfo)(nil)
var _ marshal.Marshallable = (*TableName)(nil)
var _ marshal.Marshallable = (*Termios)(nil)
var _ marshal.Marshallable = (*TimeT)(nil)
var _ marshal.Marshallable = (*TimerID)(nil)
var _ marshal.Marshallable = (*Timespec)(nil)
var _ marshal.Marshallable = (*Timeval)(nil)
var _ marshal.Marshallable = (*Tms)(nil)
var _ marshal.Marshallable = (*Utime)(nil)
var _ marshal.Marshallable = (*UtsName)(nil)
var _ marshal.Marshallable = (*WindowSize)(nil)
var _ marshal.Marshallable = (*Winsize)(nil)
var _ marshal.Marshallable = (*XTCounters)(nil)
var _ marshal.Marshallable = (*XTGetRevision)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IOCallback) SizeBytes() int {
    return 64
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOCallback) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Data))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Key))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.OpCode))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.ReqPrio))
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.FD))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Buf))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Bytes))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Offset))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Reserved2))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.ResFD))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOCallback) UnmarshalBytes(src []byte) {
    i.Data = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Key = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    i.OpCode = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.ReqPrio = int16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.FD = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Buf = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Bytes = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Offset = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Reserved2 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.ResFD = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOCallback) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOCallback) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOCallback) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IOCallback) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IOCallback) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IOCallback) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOCallback) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IOEvent) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IOEvent) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Data))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Obj))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Result))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Result2))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IOEvent) UnmarshalBytes(src []byte) {
    i.Data = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Obj = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Result = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Result2 = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOEvent) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IOEvent) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IOEvent) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IOEvent) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IOEvent) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IOEvent) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IOEvent) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (b *BPFInstruction) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (b *BPFInstruction) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(b.OpCode))
    dst = dst[2:]
    dst[0] = byte(b.JumpIfTrue)
    dst = dst[1:]
    dst[0] = byte(b.JumpIfFalse)
    dst = dst[1:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(b.K))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (b *BPFInstruction) UnmarshalBytes(src []byte) {
    b.OpCode = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    b.JumpIfTrue = uint8(src[0])
    src = src[1:]
    b.JumpIfFalse = uint8(src[0])
    src = src[1:]
    b.K = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (b *BPFInstruction) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (b *BPFInstruction) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(b))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (b *BPFInstruction) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(b), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (b *BPFInstruction) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(b)))
    hdr.Len = b.SizeBytes()
    hdr.Cap = b.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that b
    // must live until the use above.
    runtime.KeepAlive(b) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (b *BPFInstruction) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return b.CopyOutN(cc, addr, b.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (b *BPFInstruction) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(b)))
    hdr.Len = b.SizeBytes()
    hdr.Cap = b.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that b
    // must live until the use above.
    runtime.KeepAlive(b) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (b *BPFInstruction) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(b)))
    hdr.Len = b.SizeBytes()
    hdr.Cap = b.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that b
    // must live until the use above.
    runtime.KeepAlive(b) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyBPFInstructionSliceIn copies in a slice of BPFInstruction objects from the task's memory.
func CopyBPFInstructionSliceIn(cc marshal.CopyContext, addr usermem.Addr, dst []BPFInstruction) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyBPFInstructionSliceOut copies a slice of BPFInstruction objects to the task's memory.
func CopyBPFInstructionSliceOut(cc marshal.CopyContext, addr usermem.Addr, src []BPFInstruction) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeBPFInstructionSlice is like BPFInstruction.MarshalUnsafe, but for a []BPFInstruction.
func MarshalUnsafeBPFInstructionSlice(src []BPFInstruction, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyIn(dst[:(size*count)], val)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// UnmarshalUnsafeBPFInstructionSlice is like BPFInstruction.UnmarshalUnsafe, but for a []BPFInstruction.
func UnmarshalUnsafeBPFInstructionSlice(dst []BPFInstruction, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyOut(val, src[:(size*count)])
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *CapUserHeader) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *CapUserHeader) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.Version))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.Pid))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *CapUserHeader) UnmarshalBytes(src []byte) {
    c.Version = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Pid = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *CapUserHeader) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *CapUserHeader) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(c))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *CapUserHeader) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(c), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (c *CapUserHeader) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (c *CapUserHeader) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (c *CapUserHeader) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *CapUserHeader) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *CapUserData) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *CapUserData) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.Effective))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.Permitted))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.Inheritable))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *CapUserData) UnmarshalBytes(src []byte) {
    c.Effective = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Permitted = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Inheritable = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *CapUserData) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *CapUserData) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(c))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *CapUserData) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(c), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (c *CapUserData) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (c *CapUserData) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (c *CapUserData) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *CapUserData) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyCapUserDataSliceIn copies in a slice of CapUserData objects from the task's memory.
func CopyCapUserDataSliceIn(cc marshal.CopyContext, addr usermem.Addr, dst []CapUserData) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyCapUserDataSliceOut copies a slice of CapUserData objects to the task's memory.
func CopyCapUserDataSliceOut(cc marshal.CopyContext, addr usermem.Addr, src []CapUserData) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeCapUserDataSlice is like CapUserData.MarshalUnsafe, but for a []CapUserData.
func MarshalUnsafeCapUserDataSlice(src []CapUserData, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyIn(dst[:(size*count)], val)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// UnmarshalUnsafeCapUserDataSlice is like CapUserData.UnmarshalUnsafe, but for a []CapUserData.
func UnmarshalUnsafeCapUserDataSlice(dst []CapUserData, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyOut(val, src[:(size*count)])
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *Flock) SizeBytes() int {
    return 24 +
        1*4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *Flock) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(f.Type))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(f.Whence))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Start))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Len))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Pid))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *Flock) UnmarshalBytes(src []byte) {
    f.Type = int16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.Whence = int16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([4]byte(f._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    f.Start = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Len = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Pid = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(f._), src[:sizeof(byte)*4])
    src = src[1*(4):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *Flock) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *Flock) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *Flock) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *Flock) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *Flock) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *Flock) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *Flock) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FOwnerEx) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FOwnerEx) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Type))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.PID))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FOwnerEx) UnmarshalBytes(src []byte) {
    f.Type = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.PID = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FOwnerEx) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FOwnerEx) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FOwnerEx) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FOwnerEx) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FOwnerEx) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FOwnerEx) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FOwnerEx) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Statx) SizeBytes() int {
    return 80 +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Statx) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Mask))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Blksize))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Attributes))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Nlink))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.GID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Mode))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Ino))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.AttributesMask))
    dst = dst[8:]
    s.Atime.MarshalBytes(dst[:s.Atime.SizeBytes()])
    dst = dst[s.Atime.SizeBytes():]
    s.Btime.MarshalBytes(dst[:s.Btime.SizeBytes()])
    dst = dst[s.Btime.SizeBytes():]
    s.Ctime.MarshalBytes(dst[:s.Ctime.SizeBytes()])
    dst = dst[s.Ctime.SizeBytes():]
    s.Mtime.MarshalBytes(dst[:s.Mtime.SizeBytes()])
    dst = dst[s.Mtime.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.RdevMajor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.RdevMinor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.DevMajor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.DevMinor))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Statx) UnmarshalBytes(src []byte) {
    s.Mask = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Blksize = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Attributes = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Nlink = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Mode = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    s.Ino = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Size = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.AttributesMask = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Atime.UnmarshalBytes(src[:s.Atime.SizeBytes()])
    src = src[s.Atime.SizeBytes():]
    s.Btime.UnmarshalBytes(src[:s.Btime.SizeBytes()])
    src = src[s.Btime.SizeBytes():]
    s.Ctime.UnmarshalBytes(src[:s.Ctime.SizeBytes()])
    src = src[s.Ctime.SizeBytes():]
    s.Mtime.UnmarshalBytes(src[:s.Mtime.SizeBytes()])
    src = src[s.Mtime.SizeBytes():]
    s.RdevMajor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.RdevMinor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.DevMajor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.DevMinor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Statx) Packed() bool {
    return s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Statx) MarshalUnsafe(dst []byte) {
    if s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        // Type Statx doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Statx) UnmarshalUnsafe(src []byte) {
    if s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        // Type Statx doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        s.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *Statx) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        s.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *Statx) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *Statx) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        s.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Statx) WriteTo(writer io.Writer) (int64, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        // Type Statx doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Statfs) SizeBytes() int {
    return 80 +
        4*2 +
        8*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Statfs) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Type))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.BlockSize))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksFree))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksAvailable))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Files))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.FilesFree))
    dst = dst[8:]
    for idx := 0; idx < 2; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(s.FSID[idx]))
        dst = dst[4:]
    }
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.NameLength))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.FragmentSize))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Flags))
    dst = dst[8:]
    for idx := 0; idx < 4; idx++ {
        usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Spare[idx]))
        dst = dst[8:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Statfs) UnmarshalBytes(src []byte) {
    s.Type = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlockSize = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksFree = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksAvailable = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Files = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FilesFree = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 2; idx++ {
        s.FSID[idx] = int32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    s.NameLength = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FragmentSize = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 4; idx++ {
        s.Spare[idx] = uint64(usermem.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Statfs) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Statfs) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Statfs) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *Statfs) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *Statfs) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *Statfs) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Statfs) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (f *FUSEOpcode) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpcode) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(*f))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpcode) UnmarshalBytes(src []byte) {
    *f = FUSEOpcode(uint32(usermem.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpcode) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpcode) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpcode) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEOpcode) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEOpcode) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEOpcode) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpcode) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (f *FUSEOpID) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpID) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(*f))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpID) UnmarshalBytes(src []byte) {
    *f = FUSEOpID(uint64(usermem.ByteOrder.Uint64(src[:8])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpID) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpID) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEOpID) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEOpID) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEOpID) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEHeaderIn) SizeBytes() int {
    return 28 +
        (*FUSEOpcode)(nil).SizeBytes() +
        (*FUSEOpID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEHeaderIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Len))
    dst = dst[4:]
    f.Opcode.MarshalBytes(dst[:f.Opcode.SizeBytes()])
    dst = dst[f.Opcode.SizeBytes():]
    f.Unique.MarshalBytes(dst[:f.Unique.SizeBytes()])
    dst = dst[f.Unique.SizeBytes():]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.NodeID))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.GID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.PID))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEHeaderIn) UnmarshalBytes(src []byte) {
    f.Len = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Opcode.UnmarshalBytes(src[:f.Opcode.SizeBytes()])
    src = src[f.Opcode.SizeBytes():]
    f.Unique.UnmarshalBytes(src[:f.Unique.SizeBytes()])
    src = src[f.Unique.SizeBytes():]
    f.NodeID = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.PID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEHeaderIn) Packed() bool {
    return f.Opcode.Packed() && f.Unique.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEHeaderIn) MarshalUnsafe(dst []byte) {
    if f.Opcode.Packed() && f.Unique.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(f))
    } else {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fallback to MarshalBytes.
        f.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEHeaderIn) UnmarshalUnsafe(src []byte) {
    if f.Opcode.Packed() && f.Unique.Packed() {
        safecopy.CopyOut(unsafe.Pointer(f), src)
    } else {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        f.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEHeaderIn) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEHeaderIn) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEHeaderIn) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEHeaderIn) WriteTo(writer io.Writer) (int64, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        // Type FUSEHeaderIn doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEHeaderOut) SizeBytes() int {
    return 8 +
        (*FUSEOpID)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEHeaderOut) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Len))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Error))
    dst = dst[4:]
    f.Unique.MarshalBytes(dst[:f.Unique.SizeBytes()])
    dst = dst[f.Unique.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEHeaderOut) UnmarshalBytes(src []byte) {
    f.Len = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Error = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Unique.UnmarshalBytes(src[:f.Unique.SizeBytes()])
    src = src[f.Unique.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEHeaderOut) Packed() bool {
    return f.Unique.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEHeaderOut) MarshalUnsafe(dst []byte) {
    if f.Unique.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(f))
    } else {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fallback to MarshalBytes.
        f.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEHeaderOut) UnmarshalUnsafe(src []byte) {
    if f.Unique.Packed() {
        safecopy.CopyOut(unsafe.Pointer(f), src)
    } else {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        f.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEHeaderOut) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !f.Unique.Packed() {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEHeaderOut) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEHeaderOut) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !f.Unique.Packed() {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEHeaderOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Unique.Packed() {
        // Type FUSEHeaderOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEInitIn) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEInitIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Major))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Minor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.MaxReadahead))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEInitIn) UnmarshalBytes(src []byte) {
    f.Major = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Minor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxReadahead = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEInitIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEInitIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEInitIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEInitIn) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEInitIn) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEInitIn) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEInitIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEInitOut) SizeBytes() int {
    return 32 +
        4*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEInitOut) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Major))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Minor))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.MaxReadahead))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(f.MaxBackground))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(f.CongestionThreshold))
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.MaxWrite))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.TimeGran))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(f.MaxPages))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    // Padding: dst[:sizeof(uint32)*8] ~= [8]uint32{0}
    dst = dst[4*(8):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEInitOut) UnmarshalBytes(src []byte) {
    f.Major = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Minor = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxReadahead = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxBackground = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.CongestionThreshold = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.MaxWrite = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.TimeGran = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxPages = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    // Padding: ~ copy([8]uint32(f._), src[:sizeof(uint32)*8])
    src = src[4*(8):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEInitOut) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEInitOut) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEInitOut) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEInitOut) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEInitOut) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEInitOut) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEInitOut) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEGetAttrIn) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEGetAttrIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.GetAttrFlags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEGetAttrIn) UnmarshalBytes(src []byte) {
    f.GetAttrFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.Fh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEGetAttrIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEGetAttrIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEGetAttrIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEGetAttrIn) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEGetAttrIn) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEGetAttrIn) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEGetAttrIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEAttr) SizeBytes() int {
    return 88
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEAttr) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Ino))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Size))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Blocks))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Atime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Mtime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Ctime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.AtimeNsec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.MtimeNsec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.CtimeNsec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Nlink))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.GID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Rdev))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.BlkSize))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEAttr) UnmarshalBytes(src []byte) {
    f.Ino = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Blocks = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Atime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Mtime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Ctime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AtimeNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MtimeNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.CtimeNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Mode = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Nlink = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Rdev = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.BlkSize = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEAttr) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEAttr) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEAttr) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEAttr) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEAttr) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEAttr) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEAttr) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEGetAttrOut) SizeBytes() int {
    return 16 +
        (*FUSEAttr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEGetAttrOut) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.AttrValid))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.AttrValidNsec))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    f.Attr.MarshalBytes(dst[:f.Attr.SizeBytes()])
    dst = dst[f.Attr.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEGetAttrOut) UnmarshalBytes(src []byte) {
    f.AttrValid = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AttrValidNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.Attr.UnmarshalBytes(src[:f.Attr.SizeBytes()])
    src = src[f.Attr.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEGetAttrOut) Packed() bool {
    return f.Attr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEGetAttrOut) MarshalUnsafe(dst []byte) {
    if f.Attr.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(f))
    } else {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fallback to MarshalBytes.
        f.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEGetAttrOut) UnmarshalUnsafe(src []byte) {
    if f.Attr.Packed() {
        safecopy.CopyOut(unsafe.Pointer(f), src)
    } else {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        f.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEGetAttrOut) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEGetAttrOut) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEGetAttrOut) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEGetAttrOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Attr.Packed() {
        // Type FUSEGetAttrOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEEntryOut) SizeBytes() int {
    return 40 +
        (*FUSEAttr)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEEntryOut) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.NodeID))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Generation))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.EntryValid))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.AttrValid))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.EntryValidNSec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.AttrValidNSec))
    dst = dst[4:]
    f.Attr.MarshalBytes(dst[:f.Attr.SizeBytes()])
    dst = dst[f.Attr.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEEntryOut) UnmarshalBytes(src []byte) {
    f.NodeID = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Generation = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.EntryValid = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AttrValid = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.EntryValidNSec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.AttrValidNSec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Attr.UnmarshalBytes(src[:f.Attr.SizeBytes()])
    src = src[f.Attr.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEEntryOut) Packed() bool {
    return f.Attr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEEntryOut) MarshalUnsafe(dst []byte) {
    if f.Attr.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(f))
    } else {
        // Type FUSEEntryOut doesn't have a packed layout in memory, fallback to MarshalBytes.
        f.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEEntryOut) UnmarshalUnsafe(src []byte) {
    if f.Attr.Packed() {
        safecopy.CopyOut(unsafe.Pointer(f), src)
    } else {
        // Type FUSEEntryOut doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        f.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEEntryOut) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEEntryOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        f.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEEntryOut) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEEntryOut) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !f.Attr.Packed() {
        // Type FUSEEntryOut doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(f.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        f.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEEntryOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Attr.Packed() {
        // Type FUSEEntryOut doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEOpenIn) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpenIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpenIn) UnmarshalBytes(src []byte) {
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpenIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpenIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpenIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEOpenIn) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEOpenIn) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEOpenIn) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpenIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEOpenOut) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEOpenOut) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.OpenFlag))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEOpenOut) UnmarshalBytes(src []byte) {
    f.Fh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.OpenFlag = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpenOut) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEOpenOut) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEOpenOut) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEOpenOut) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEOpenOut) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEOpenOut) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEOpenOut) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEReadIn) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEReadIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.ReadFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEReadIn) UnmarshalBytes(src []byte) {
    f.Fh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.ReadFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEReadIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEReadIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEReadIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEReadIn) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEReadIn) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEReadIn) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEReadIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEWriteIn) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEWriteIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.WriteFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEWriteIn) UnmarshalBytes(src []byte) {
    f.Fh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.WriteFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEWriteIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEWriteIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEWriteIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEWriteIn) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEWriteIn) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEWriteIn) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEWriteIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEWriteOut) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEWriteOut) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEWriteOut) UnmarshalBytes(src []byte) {
    f.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEWriteOut) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEWriteOut) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEWriteOut) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEWriteOut) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEWriteOut) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEWriteOut) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEWriteOut) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEReleaseIn) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEReleaseIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.ReleaseFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEReleaseIn) UnmarshalBytes(src []byte) {
    f.Fh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.ReleaseFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEReleaseIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEReleaseIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEReleaseIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEReleaseIn) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEReleaseIn) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEReleaseIn) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEReleaseIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSECreateMeta) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSECreateMeta) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Umask))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSECreateMeta) UnmarshalBytes(src []byte) {
    f.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Mode = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Umask = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSECreateMeta) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSECreateMeta) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSECreateMeta) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSECreateMeta) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSECreateMeta) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSECreateMeta) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSECreateMeta) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEMknodMeta) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEMknodMeta) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Rdev))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Umask))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEMknodMeta) UnmarshalBytes(src []byte) {
    f.Mode = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Rdev = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Umask = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEMknodMeta) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEMknodMeta) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEMknodMeta) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEMknodMeta) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEMknodMeta) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEMknodMeta) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEMknodMeta) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEMkdirMeta) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEMkdirMeta) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Umask))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEMkdirMeta) UnmarshalBytes(src []byte) {
    f.Mode = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Umask = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEMkdirMeta) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEMkdirMeta) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEMkdirMeta) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEMkdirMeta) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEMkdirMeta) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEMkdirMeta) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEMkdirMeta) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSEDirentMeta) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSEDirentMeta) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Ino))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Off))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.NameLen))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Type))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSEDirentMeta) UnmarshalBytes(src []byte) {
    f.Ino = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Off = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.NameLen = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Type = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEDirentMeta) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSEDirentMeta) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSEDirentMeta) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSEDirentMeta) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSEDirentMeta) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSEDirentMeta) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSEDirentMeta) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (f *FUSESetAttrIn) SizeBytes() int {
    return 88
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (f *FUSESetAttrIn) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Valid))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Size))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Atime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Mtime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(f.Ctime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.AtimeNsec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.MtimeNsec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.CtimeNsec))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(f.GID))
    dst = dst[4:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (f *FUSESetAttrIn) UnmarshalBytes(src []byte) {
    f.Valid = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.Fh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.LockOwner = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Atime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Mtime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Ctime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AtimeNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MtimeNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.CtimeNsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Mode = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    f.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSESetAttrIn) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (f *FUSESetAttrIn) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(f))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (f *FUSESetAttrIn) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(f), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (f *FUSESetAttrIn) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (f *FUSESetAttrIn) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (f *FUSESetAttrIn) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (f *FUSESetAttrIn) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that f
    // must live until the use above.
    runtime.KeepAlive(f) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RobustListHead) SizeBytes() int {
    return 24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RobustListHead) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.List))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.FutexOffset))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.ListOpPending))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RobustListHead) UnmarshalBytes(src []byte) {
    r.List = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.FutexOffset = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.ListOpPending = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RobustListHead) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RobustListHead) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(r))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RobustListHead) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(r), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *RobustListHead) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (r *RobustListHead) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (r *RobustListHead) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RobustListHead) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (d *DigestMetadata) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (d *DigestMetadata) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(d.DigestAlgorithm))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(d.DigestSize))
    dst = dst[2:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (d *DigestMetadata) UnmarshalBytes(src []byte) {
    d.DigestAlgorithm = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    d.DigestSize = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (d *DigestMetadata) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (d *DigestMetadata) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(d))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (d *DigestMetadata) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(d), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (d *DigestMetadata) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(d)))
    hdr.Len = d.SizeBytes()
    hdr.Cap = d.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that d
    // must live until the use above.
    runtime.KeepAlive(d) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (d *DigestMetadata) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return d.CopyOutN(cc, addr, d.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (d *DigestMetadata) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(d)))
    hdr.Len = d.SizeBytes()
    hdr.Cap = d.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that d
    // must live until the use above.
    runtime.KeepAlive(d) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (d *DigestMetadata) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(d)))
    hdr.Len = d.SizeBytes()
    hdr.Cap = d.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that d
    // must live until the use above.
    runtime.KeepAlive(d) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPCPerm) SizeBytes() int {
    return 48
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPCPerm) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Key))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.GID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.CUID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.CGID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.Mode))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.Seq))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    // Padding: dst[:sizeof(uint32)] ~= uint32(0)
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.unused1))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.unused2))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPCPerm) UnmarshalBytes(src []byte) {
    i.Key = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CUID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CGID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Mode = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    i.Seq = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    // Padding: var _ uint32 ~= src[:sizeof(uint32)]
    src = src[4:]
    i.unused1 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.unused2 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPCPerm) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPCPerm) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPCPerm) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IPCPerm) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IPCPerm) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IPCPerm) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPCPerm) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Sysinfo) SizeBytes() int {
    return 78 +
        8*3 +
        1*6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Sysinfo) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Uptime))
    dst = dst[8:]
    for idx := 0; idx < 3; idx++ {
        usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Loads[idx]))
        dst = dst[8:]
    }
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.TotalRAM))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.FreeRAM))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.SharedRAM))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.BufferRAM))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.TotalSwap))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.FreeSwap))
    dst = dst[8:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Procs))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*6] ~= [6]byte{0}
    dst = dst[1*(6):]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.TotalHigh))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.FreeHigh))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Unit))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Sysinfo) UnmarshalBytes(src []byte) {
    s.Uptime = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 3; idx++ {
        s.Loads[idx] = uint64(usermem.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    s.TotalRAM = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FreeRAM = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SharedRAM = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BufferRAM = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.TotalSwap = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FreeSwap = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Procs = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([6]byte(s._), src[:sizeof(byte)*6])
    src = src[1*(6):]
    s.TotalHigh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FreeHigh = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Unit = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Sysinfo) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Sysinfo) MarshalUnsafe(dst []byte) {
    // Type Sysinfo doesn't have a packed layout in memory, fallback to MarshalBytes.
    s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Sysinfo) UnmarshalUnsafe(src []byte) {
    // Type Sysinfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *Sysinfo) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Type Sysinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    s.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *Sysinfo) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *Sysinfo) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Type Sysinfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    s.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Sysinfo) WriteTo(writer io.Writer) (int64, error) {
    // Type Sysinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, s.SizeBytes())
    s.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (n *NumaPolicy) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *NumaPolicy) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(*n))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *NumaPolicy) UnmarshalBytes(src []byte) {
    *n = NumaPolicy(int32(usermem.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NumaPolicy) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *NumaPolicy) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(n))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *NumaPolicy) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(n), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (n *NumaPolicy) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (n *NumaPolicy) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (n *NumaPolicy) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (n *NumaPolicy) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IFReq) SizeBytes() int {
    return 0 +
        1*IFNAMSIZ +
        1*24
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IFReq) MarshalBytes(dst []byte) {
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.IFName[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 24; idx++ {
        dst[0] = byte(i.Data[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IFReq) UnmarshalBytes(src []byte) {
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.IFName[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < 24; idx++ {
        i.Data[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IFReq) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IFReq) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IFReq) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IFReq) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IFReq) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IFReq) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IFReq) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IFConf) SizeBytes() int {
    return 12 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IFConf) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Len))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Ptr))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IFConf) UnmarshalBytes(src []byte) {
    i.Len = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(i._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    i.Ptr = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IFConf) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IFConf) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IFConf) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IFConf) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IFConf) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IFConf) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IFConf) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTEntry) SizeBytes() int {
    return 12 +
        (*IPTIP)(nil).SizeBytes() +
        (*XTCounters)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTEntry) MarshalBytes(dst []byte) {
    i.IP.MarshalBytes(dst[:i.IP.SizeBytes()])
    dst = dst[i.IP.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NFCache))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.TargetOffset))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.NextOffset))
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Comeback))
    dst = dst[4:]
    i.Counters.MarshalBytes(dst[:i.Counters.SizeBytes()])
    dst = dst[i.Counters.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTEntry) UnmarshalBytes(src []byte) {
    i.IP.UnmarshalBytes(src[:i.IP.SizeBytes()])
    src = src[i.IP.SizeBytes():]
    i.NFCache = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.TargetOffset = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.NextOffset = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Comeback = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Counters.UnmarshalBytes(src[:i.Counters.SizeBytes()])
    src = src[i.Counters.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTEntry) Packed() bool {
    return i.Counters.Packed() && i.IP.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTEntry) MarshalUnsafe(dst []byte) {
    if i.Counters.Packed() && i.IP.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IPTEntry doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTEntry) UnmarshalUnsafe(src []byte) {
    if i.Counters.Packed() && i.IP.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IPTEntry doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IPTEntry) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IP.Packed() {
        // Type IPTEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IPTEntry) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IPTEntry) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !i.Counters.Packed() && i.IP.Packed() {
        // Type IPTEntry doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTEntry) WriteTo(writer io.Writer) (int64, error) {
    if !i.Counters.Packed() && i.IP.Packed() {
        // Type IPTEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTIP) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTIP) MarshalBytes(dst []byte) {
    i.Src.MarshalBytes(dst[:i.Src.SizeBytes()])
    dst = dst[i.Src.SizeBytes():]
    i.Dst.MarshalBytes(dst[:i.Dst.SizeBytes()])
    dst = dst[i.Dst.SizeBytes():]
    i.SrcMask.MarshalBytes(dst[:i.SrcMask.SizeBytes()])
    dst = dst[i.SrcMask.SizeBytes():]
    i.DstMask.MarshalBytes(dst[:i.DstMask.SizeBytes()])
    dst = dst[i.DstMask.SizeBytes():]
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterfaceMask[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterfaceMask[idx])
        dst = dst[1:]
    }
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.Protocol))
    dst = dst[2:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.InverseFlags)
    dst = dst[1:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTIP) UnmarshalBytes(src []byte) {
    i.Src.UnmarshalBytes(src[:i.Src.SizeBytes()])
    src = src[i.Src.SizeBytes():]
    i.Dst.UnmarshalBytes(src[:i.Dst.SizeBytes()])
    src = src[i.Dst.SizeBytes():]
    i.SrcMask.UnmarshalBytes(src[:i.SrcMask.SizeBytes()])
    src = src[i.SrcMask.SizeBytes():]
    i.DstMask.UnmarshalBytes(src[:i.DstMask.SizeBytes()])
    src = src[i.DstMask.SizeBytes():]
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    i.Protocol = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.InverseFlags = uint8(src[0])
    src = src[1:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTIP) Packed() bool {
    return i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTIP) MarshalUnsafe(dst []byte) {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IPTIP doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTIP) UnmarshalUnsafe(src []byte) {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IPTIP doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IPTIP) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IPTIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IPTIP) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IPTIP) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IPTIP doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTIP) WriteTo(writer io.Writer) (int64, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IPTIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTCounters) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTCounters) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(x.Pcnt))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(x.Bcnt))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTCounters) UnmarshalBytes(src []byte) {
    x.Pcnt = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    x.Bcnt = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTCounters) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTCounters) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(x))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTCounters) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(x), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (x *XTCounters) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (x *XTCounters) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (x *XTCounters) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTCounters) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (x *XTGetRevision) SizeBytes() int {
    return 1 +
        (*ExtensionName)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (x *XTGetRevision) MarshalBytes(dst []byte) {
    x.Name.MarshalBytes(dst[:x.Name.SizeBytes()])
    dst = dst[x.Name.SizeBytes():]
    dst[0] = byte(x.Revision)
    dst = dst[1:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (x *XTGetRevision) UnmarshalBytes(src []byte) {
    x.Name.UnmarshalBytes(src[:x.Name.SizeBytes()])
    src = src[x.Name.SizeBytes():]
    x.Revision = uint8(src[0])
    src = src[1:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTGetRevision) Packed() bool {
    return x.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (x *XTGetRevision) MarshalUnsafe(dst []byte) {
    if x.Name.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(x))
    } else {
        // Type XTGetRevision doesn't have a packed layout in memory, fallback to MarshalBytes.
        x.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (x *XTGetRevision) UnmarshalUnsafe(src []byte) {
    if x.Name.Packed() {
        safecopy.CopyOut(unsafe.Pointer(x), src)
    } else {
        // Type XTGetRevision doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        x.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (x *XTGetRevision) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        // Type XTGetRevision doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        x.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (x *XTGetRevision) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (x *XTGetRevision) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !x.Name.Packed() {
        // Type XTGetRevision doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(x.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        x.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (x *XTGetRevision) WriteTo(writer io.Writer) (int64, error) {
    if !x.Name.Packed() {
        // Type XTGetRevision doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that x
    // must live until the use above.
    runtime.KeepAlive(x) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTGetinfo) SizeBytes() int {
    return 12 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTGetinfo) MarshalBytes(dst []byte) {
    i.Name.MarshalBytes(dst[:i.Name.SizeBytes()])
    dst = dst[i.Name.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTGetinfo) UnmarshalBytes(src []byte) {
    i.Name.UnmarshalBytes(src[:i.Name.SizeBytes()])
    src = src[i.Name.SizeBytes():]
    i.ValidHooks = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumEntries = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTGetinfo) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTGetinfo) MarshalUnsafe(dst []byte) {
    if i.Name.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IPTGetinfo doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTGetinfo) UnmarshalUnsafe(src []byte) {
    if i.Name.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IPTGetinfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IPTGetinfo) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IPTGetinfo) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IPTGetinfo) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetinfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTGetinfo) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IPTGetinfo doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IPTGetEntries) SizeBytes() int {
    return 4 +
        (*TableName)(nil).SizeBytes() +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IPTGetEntries) MarshalBytes(dst []byte) {
    i.Name.MarshalBytes(dst[:i.Name.SizeBytes()])
    dst = dst[i.Name.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IPTGetEntries) UnmarshalBytes(src []byte) {
    i.Name.UnmarshalBytes(src[:i.Name.SizeBytes()])
    src = src[i.Name.SizeBytes():]
    i.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(i._), src[:sizeof(byte)*4])
    src = src[1*(4):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTGetEntries) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IPTGetEntries) MarshalUnsafe(dst []byte) {
    if i.Name.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IPTGetEntries doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IPTGetEntries) UnmarshalUnsafe(src []byte) {
    if i.Name.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IPTGetEntries doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IPTGetEntries) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IPTGetEntries) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IPTGetEntries) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !i.Name.Packed() {
        // Type IPTGetEntries doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IPTGetEntries) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IPTGetEntries doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (e *ExtensionName) SizeBytes() int {
    return 1 * XT_EXTENSION_MAXNAMELEN
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (e *ExtensionName) MarshalBytes(dst []byte) {
    for idx := 0; idx < XT_EXTENSION_MAXNAMELEN; idx++ {
        dst[0] = byte(e[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (e *ExtensionName) UnmarshalBytes(src []byte) {
    for idx := 0; idx < XT_EXTENSION_MAXNAMELEN; idx++ {
        e[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *ExtensionName) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (e *ExtensionName) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(e))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (e *ExtensionName) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(e), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (e *ExtensionName) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (e *ExtensionName) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (e *ExtensionName) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (e *ExtensionName) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that e
    // must live until the use above.
    runtime.KeepAlive(e) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (t *TableName) SizeBytes() int {
    return 1 * XT_TABLE_MAXNAMELEN
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *TableName) MarshalBytes(dst []byte) {
    for idx := 0; idx < XT_TABLE_MAXNAMELEN; idx++ {
        dst[0] = byte(t[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *TableName) UnmarshalBytes(src []byte) {
    for idx := 0; idx < XT_TABLE_MAXNAMELEN; idx++ {
        t[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TableName) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *TableName) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *TableName) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *TableName) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *TableName) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *TableName) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *TableName) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IP6TReplace) SizeBytes() int {
    return 24 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IP6TReplace) MarshalBytes(dst []byte) {
    i.Name.MarshalBytes(dst[:i.Name.SizeBytes()])
    dst = dst[i.Name.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NumCounters))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(i.Counters))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IP6TReplace) UnmarshalBytes(src []byte) {
    i.Name.UnmarshalBytes(src[:i.Name.SizeBytes()])
    src = src[i.Name.SizeBytes():]
    i.ValidHooks = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.NumEntries = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(usermem.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumCounters = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Counters = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TReplace) Packed() bool {
    return i.Name.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IP6TReplace) MarshalUnsafe(dst []byte) {
    if i.Name.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IP6TReplace doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IP6TReplace) UnmarshalUnsafe(src []byte) {
    if i.Name.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IP6TReplace doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IP6TReplace) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
        // Type IP6TReplace doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IP6TReplace) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IP6TReplace) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !i.Name.Packed() {
        // Type IP6TReplace doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IP6TReplace) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
        // Type IP6TReplace doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IP6TEntry) SizeBytes() int {
    return 12 +
        (*IP6TIP)(nil).SizeBytes() +
        1*4 +
        (*XTCounters)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IP6TEntry) MarshalBytes(dst []byte) {
    i.IPv6.MarshalBytes(dst[:i.IPv6.SizeBytes()])
    dst = dst[i.IPv6.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.NFCache))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.TargetOffset))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.NextOffset))
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(i.Comeback))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    i.Counters.MarshalBytes(dst[:i.Counters.SizeBytes()])
    dst = dst[i.Counters.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IP6TEntry) UnmarshalBytes(src []byte) {
    i.IPv6.UnmarshalBytes(src[:i.IPv6.SizeBytes()])
    src = src[i.IPv6.SizeBytes():]
    i.NFCache = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.TargetOffset = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.NextOffset = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Comeback = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(i._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    i.Counters.UnmarshalBytes(src[:i.Counters.SizeBytes()])
    src = src[i.Counters.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TEntry) Packed() bool {
    return i.Counters.Packed() && i.IPv6.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IP6TEntry) MarshalUnsafe(dst []byte) {
    if i.Counters.Packed() && i.IPv6.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IP6TEntry doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IP6TEntry) UnmarshalUnsafe(src []byte) {
    if i.Counters.Packed() && i.IPv6.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IP6TEntry doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IP6TEntry) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IPv6.Packed() {
        // Type IP6TEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IP6TEntry) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IP6TEntry) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !i.Counters.Packed() && i.IPv6.Packed() {
        // Type IP6TEntry doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IP6TEntry) WriteTo(writer io.Writer) (int64, error) {
    if !i.Counters.Packed() && i.IPv6.Packed() {
        // Type IP6TEntry doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *IP6TIP) SizeBytes() int {
    return 5 +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*3
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *IP6TIP) MarshalBytes(dst []byte) {
    i.Src.MarshalBytes(dst[:i.Src.SizeBytes()])
    dst = dst[i.Src.SizeBytes():]
    i.Dst.MarshalBytes(dst[:i.Dst.SizeBytes()])
    dst = dst[i.Dst.SizeBytes():]
    i.SrcMask.MarshalBytes(dst[:i.SrcMask.SizeBytes()])
    dst = dst[i.SrcMask.SizeBytes():]
    i.DstMask.MarshalBytes(dst[:i.DstMask.SizeBytes()])
    dst = dst[i.DstMask.SizeBytes():]
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterfaceMask[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterfaceMask[idx])
        dst = dst[1:]
    }
    usermem.ByteOrder.PutUint16(dst[:2], uint16(i.Protocol))
    dst = dst[2:]
    dst[0] = byte(i.TOS)
    dst = dst[1:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.InverseFlags)
    dst = dst[1:]
    // Padding: dst[:sizeof(byte)*3] ~= [3]byte{0}
    dst = dst[1*(3):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *IP6TIP) UnmarshalBytes(src []byte) {
    i.Src.UnmarshalBytes(src[:i.Src.SizeBytes()])
    src = src[i.Src.SizeBytes():]
    i.Dst.UnmarshalBytes(src[:i.Dst.SizeBytes()])
    src = src[i.Dst.SizeBytes():]
    i.SrcMask.UnmarshalBytes(src[:i.SrcMask.SizeBytes()])
    src = src[i.SrcMask.SizeBytes():]
    i.DstMask.UnmarshalBytes(src[:i.DstMask.SizeBytes()])
    src = src[i.DstMask.SizeBytes():]
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    i.Protocol = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.TOS = uint8(src[0])
    src = src[1:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.InverseFlags = uint8(src[0])
    src = src[1:]
    // Padding: ~ copy([3]byte(i._), src[:sizeof(byte)*3])
    src = src[1*(3):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TIP) Packed() bool {
    return i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *IP6TIP) MarshalUnsafe(dst []byte) {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type IP6TIP doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *IP6TIP) UnmarshalUnsafe(src []byte) {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type IP6TIP doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *IP6TIP) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IP6TIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *IP6TIP) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *IP6TIP) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IP6TIP doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *IP6TIP) WriteTo(writer io.Writer) (int64, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        // Type IP6TIP doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SockAddrNetlink) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrNetlink) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint16)] ~= uint16(0)
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.PortID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Groups))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrNetlink) UnmarshalBytes(src []byte) {
    s.Family = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: var _ uint16 ~= src[:sizeof(uint16)]
    src = src[2:]
    s.PortID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Groups = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrNetlink) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrNetlink) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrNetlink) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SockAddrNetlink) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SockAddrNetlink) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SockAddrNetlink) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrNetlink) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (p *PollFD) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (p *PollFD) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(p.Events))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(p.REvents))
    dst = dst[2:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (p *PollFD) UnmarshalBytes(src []byte) {
    p.FD = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Events = int16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    p.REvents = int16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *PollFD) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (p *PollFD) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(p))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (p *PollFD) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(p), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (p *PollFD) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (p *PollFD) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (p *PollFD) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *PollFD) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that p
    // must live until the use above.
    runtime.KeepAlive(p) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyPollFDSliceIn copies in a slice of PollFD objects from the task's memory.
func CopyPollFDSliceIn(cc marshal.CopyContext, addr usermem.Addr, dst []PollFD) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyPollFDSliceOut copies a slice of PollFD objects to the task's memory.
func CopyPollFDSliceOut(cc marshal.CopyContext, addr usermem.Addr, src []PollFD) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafePollFDSlice is like PollFD.MarshalUnsafe, but for a []PollFD.
func MarshalUnsafePollFDSlice(src []PollFD, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyIn(dst[:(size*count)], val)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// UnmarshalUnsafePollFDSlice is like PollFD.UnmarshalUnsafe, but for a []PollFD.
func UnmarshalUnsafePollFDSlice(dst []PollFD, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyOut(val, src[:(size*count)])
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *RSeqCriticalSection) SizeBytes() int {
    return 32
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *RSeqCriticalSection) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(r.Version))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(r.Flags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.Start))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.PostCommitOffset))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.Abort))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *RSeqCriticalSection) UnmarshalBytes(src []byte) {
    r.Version = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Start = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.PostCommitOffset = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.Abort = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RSeqCriticalSection) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *RSeqCriticalSection) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(r))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *RSeqCriticalSection) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(r), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *RSeqCriticalSection) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (r *RSeqCriticalSection) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (r *RSeqCriticalSection) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *RSeqCriticalSection) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *Rusage) SizeBytes() int {
    return 112 +
        (*Timeval)(nil).SizeBytes() +
        (*Timeval)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *Rusage) MarshalBytes(dst []byte) {
    r.UTime.MarshalBytes(dst[:r.UTime.SizeBytes()])
    dst = dst[r.UTime.SizeBytes():]
    r.STime.MarshalBytes(dst[:r.STime.SizeBytes()])
    dst = dst[r.STime.SizeBytes():]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.MaxRSS))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.IXRSS))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.IDRSS))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.ISRSS))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.MinFlt))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.MajFlt))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.NSwap))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.InBlock))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.OuBlock))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.MsgSnd))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.MsgRcv))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.NSignals))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.NVCSw))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(r.NIvCSw))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *Rusage) UnmarshalBytes(src []byte) {
    r.UTime.UnmarshalBytes(src[:r.UTime.SizeBytes()])
    src = src[r.UTime.SizeBytes():]
    r.STime.UnmarshalBytes(src[:r.STime.SizeBytes()])
    src = src[r.STime.SizeBytes():]
    r.MaxRSS = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.IXRSS = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.IDRSS = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.ISRSS = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MinFlt = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MajFlt = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NSwap = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.InBlock = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.OuBlock = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MsgSnd = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MsgRcv = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NSignals = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NVCSw = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NIvCSw = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *Rusage) Packed() bool {
    return r.STime.Packed() && r.UTime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (r *Rusage) MarshalUnsafe(dst []byte) {
    if r.STime.Packed() && r.UTime.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(r))
    } else {
        // Type Rusage doesn't have a packed layout in memory, fallback to MarshalBytes.
        r.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (r *Rusage) UnmarshalUnsafe(src []byte) {
    if r.STime.Packed() && r.UTime.Packed() {
        safecopy.CopyOut(unsafe.Pointer(r), src)
    } else {
        // Type Rusage doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        r.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *Rusage) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !r.STime.Packed() && r.UTime.Packed() {
        // Type Rusage doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
        r.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (r *Rusage) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (r *Rusage) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !r.STime.Packed() && r.UTime.Packed() {
        // Type Rusage doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(r.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        r.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (r *Rusage) WriteTo(writer io.Writer) (int64, error) {
    if !r.STime.Packed() && r.UTime.Packed() {
        // Type Rusage doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, r.SizeBytes())
        r.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that r
    // must live until the use above.
    runtime.KeepAlive(r) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SeccompData) SizeBytes() int {
    return 16 +
        8*6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SeccompData) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Nr))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Arch))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.InstructionPointer))
    dst = dst[8:]
    for idx := 0; idx < 6; idx++ {
        usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Args[idx]))
        dst = dst[8:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SeccompData) UnmarshalBytes(src []byte) {
    s.Nr = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Arch = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.InstructionPointer = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 6; idx++ {
        s.Args[idx] = uint64(usermem.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SeccompData) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SeccompData) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SeccompData) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SeccompData) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SeccompData) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SeccompData) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SeccompData) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Sembuf) SizeBytes() int {
    return 6
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Sembuf) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.SemNum))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.SemOp))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.SemFlg))
    dst = dst[2:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Sembuf) UnmarshalBytes(src []byte) {
    s.SemNum = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.SemOp = int16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.SemFlg = int16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Sembuf) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Sembuf) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Sembuf) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *Sembuf) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *Sembuf) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *Sembuf) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Sembuf) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopySembufSliceIn copies in a slice of Sembuf objects from the task's memory.
func CopySembufSliceIn(cc marshal.CopyContext, addr usermem.Addr, dst []Sembuf) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopySembufSliceOut copies a slice of Sembuf objects to the task's memory.
func CopySembufSliceOut(cc marshal.CopyContext, addr usermem.Addr, src []Sembuf) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeSembufSlice is like Sembuf.MarshalUnsafe, but for a []Sembuf.
func MarshalUnsafeSembufSlice(src []Sembuf, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyIn(dst[:(size*count)], val)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// UnmarshalUnsafeSembufSlice is like Sembuf.UnmarshalUnsafe, but for a []Sembuf.
func UnmarshalUnsafeSembufSlice(dst []Sembuf, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyOut(val, src[:(size*count)])
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *ShmidDS) SizeBytes() int {
    return 40 +
        (*IPCPerm)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *ShmidDS) MarshalBytes(dst []byte) {
    s.ShmPerm.MarshalBytes(dst[:s.ShmPerm.SizeBytes()])
    dst = dst[s.ShmPerm.SizeBytes():]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmSegsz))
    dst = dst[8:]
    s.ShmAtime.MarshalBytes(dst[:s.ShmAtime.SizeBytes()])
    dst = dst[s.ShmAtime.SizeBytes():]
    s.ShmDtime.MarshalBytes(dst[:s.ShmDtime.SizeBytes()])
    dst = dst[s.ShmDtime.SizeBytes():]
    s.ShmCtime.MarshalBytes(dst[:s.ShmCtime.SizeBytes()])
    dst = dst[s.ShmCtime.SizeBytes():]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.ShmCpid))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.ShmLpid))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmNattach))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Unused4))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Unused5))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *ShmidDS) UnmarshalBytes(src []byte) {
    s.ShmPerm.UnmarshalBytes(src[:s.ShmPerm.SizeBytes()])
    src = src[s.ShmPerm.SizeBytes():]
    s.ShmSegsz = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmAtime.UnmarshalBytes(src[:s.ShmAtime.SizeBytes()])
    src = src[s.ShmAtime.SizeBytes():]
    s.ShmDtime.UnmarshalBytes(src[:s.ShmDtime.SizeBytes()])
    src = src[s.ShmDtime.SizeBytes():]
    s.ShmCtime.UnmarshalBytes(src[:s.ShmCtime.SizeBytes()])
    src = src[s.ShmCtime.SizeBytes():]
    s.ShmCpid = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.ShmLpid = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.ShmNattach = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Unused4 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Unused5 = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *ShmidDS) Packed() bool {
    return s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *ShmidDS) MarshalUnsafe(dst []byte) {
    if s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        // Type ShmidDS doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *ShmidDS) UnmarshalUnsafe(src []byte) {
    if s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        // Type ShmidDS doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        s.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *ShmidDS) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        // Type ShmidDS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        s.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *ShmidDS) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *ShmidDS) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        // Type ShmidDS doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        s.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *ShmidDS) WriteTo(writer io.Writer) (int64, error) {
    if !s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        // Type ShmidDS doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *ShmParams) SizeBytes() int {
    return 40
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *ShmParams) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmMax))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmMin))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmMni))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmSeg))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmAll))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *ShmParams) UnmarshalBytes(src []byte) {
    s.ShmMax = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmMin = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmMni = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmSeg = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmAll = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *ShmParams) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *ShmParams) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *ShmParams) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *ShmParams) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *ShmParams) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *ShmParams) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *ShmParams) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *ShmInfo) SizeBytes() int {
    return 44 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *ShmInfo) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.UsedIDs))
    dst = dst[4:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmTot))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmRss))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.ShmSwp))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.SwapAttempts))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.SwapSuccesses))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *ShmInfo) UnmarshalBytes(src []byte) {
    s.UsedIDs = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: ~ copy([4]byte(s._), src[:sizeof(byte)*4])
    src = src[1*(4):]
    s.ShmTot = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmRss = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmSwp = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SwapAttempts = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SwapSuccesses = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *ShmInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *ShmInfo) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *ShmInfo) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *ShmInfo) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *ShmInfo) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *ShmInfo) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *ShmInfo) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (s *SignalSet) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalSet) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(*s))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalSet) UnmarshalBytes(src []byte) {
    *s = SignalSet(uint64(usermem.ByteOrder.Uint64(src[:8])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalSet) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalSet) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalSet) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalSet) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SignalSet) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SignalSet) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SignalSet) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *Sigevent) SizeBytes() int {
    return 20 +
        1*44
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *Sigevent) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Value))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Signo))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Notify))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Tid))
    dst = dst[4:]
    for idx := 0; idx < 44; idx++ {
        dst[0] = byte(s.UnRemainder[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *Sigevent) UnmarshalBytes(src []byte) {
    s.Value = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Signo = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Notify = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Tid = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 44; idx++ {
        s.UnRemainder[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Sigevent) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *Sigevent) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *Sigevent) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *Sigevent) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *Sigevent) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *Sigevent) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *Sigevent) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SignalfdSiginfo) SizeBytes() int {
    return 82 +
        1*48
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SignalfdSiginfo) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Signo))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Errno))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Code))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.PID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.FD))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.TID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Band))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Overrun))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.TrapNo))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Status))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Int))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Ptr))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.UTime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.STime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Addr))
    dst = dst[8:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.AddrLSB))
    dst = dst[2:]
    // Padding: dst[:sizeof(uint8)*48] ~= [48]uint8{0}
    dst = dst[1*(48):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SignalfdSiginfo) UnmarshalBytes(src []byte) {
    s.Signo = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Errno = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Code = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.PID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.FD = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.TID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Band = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Overrun = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.TrapNo = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Status = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Int = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Ptr = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.UTime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.STime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Addr = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.AddrLSB = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([48]uint8(s._), src[:sizeof(uint8)*48])
    src = src[1*(48):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalfdSiginfo) Packed() bool {
    return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SignalfdSiginfo) MarshalUnsafe(dst []byte) {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fallback to MarshalBytes.
    s.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SignalfdSiginfo) UnmarshalUnsafe(src []byte) {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fallback to UnmarshalBytes.
    s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SignalfdSiginfo) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    s.MarshalBytes(buf) // escapes: fallback.
    return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SignalfdSiginfo) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SignalfdSiginfo) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fall back to UnmarshalBytes.
    buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Unmarshal unconditionally. If we had a short copy-in, this results in a
    // partially unmarshalled struct.
    s.UnmarshalBytes(buf) // escapes: fallback.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SignalfdSiginfo) WriteTo(writer io.Writer) (int64, error) {
    // Type SignalfdSiginfo doesn't have a packed layout in memory, fall back to MarshalBytes.
    buf := make([]byte, s.SizeBytes())
    s.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *InetAddr) SizeBytes() int {
    return 1 * 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *InetAddr) MarshalBytes(dst []byte) {
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(i[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *InetAddr) UnmarshalBytes(src []byte) {
    for idx := 0; idx < 4; idx++ {
        i[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InetAddr) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *InetAddr) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *InetAddr) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *InetAddr) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *InetAddr) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *InetAddr) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *InetAddr) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SockAddrInet) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        1*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrInet) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Port))
    dst = dst[2:]
    s.Addr.MarshalBytes(dst[:s.Addr.SizeBytes()])
    dst = dst[s.Addr.SizeBytes():]
    // Padding: dst[:sizeof(uint8)*8] ~= [8]uint8{0}
    dst = dst[1*(8):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrInet) UnmarshalBytes(src []byte) {
    s.Family = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Port = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Addr.UnmarshalBytes(src[:s.Addr.SizeBytes()])
    src = src[s.Addr.SizeBytes():]
    // Padding: ~ copy([8]uint8(s._), src[:sizeof(uint8)*8])
    src = src[1*(8):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrInet) Packed() bool {
    return s.Addr.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrInet) MarshalUnsafe(dst []byte) {
    if s.Addr.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(s))
    } else {
        // Type SockAddrInet doesn't have a packed layout in memory, fallback to MarshalBytes.
        s.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrInet) UnmarshalUnsafe(src []byte) {
    if s.Addr.Packed() {
        safecopy.CopyOut(unsafe.Pointer(s), src)
    } else {
        // Type SockAddrInet doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        s.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SockAddrInet) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !s.Addr.Packed() {
        // Type SockAddrInet doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        s.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SockAddrInet) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SockAddrInet) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !s.Addr.Packed() {
        // Type SockAddrInet doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(s.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        s.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrInet) WriteTo(writer io.Writer) (int64, error) {
    if !s.Addr.Packed() {
        // Type SockAddrInet doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *Inet6Addr) SizeBytes() int {
    return 1 * 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *Inet6Addr) MarshalBytes(dst []byte) {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(i[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *Inet6Addr) UnmarshalBytes(src []byte) {
    for idx := 0; idx < 16; idx++ {
        i[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Inet6Addr) Packed() bool {
    // Array newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *Inet6Addr) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(i))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *Inet6Addr) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(i), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *Inet6Addr) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *Inet6Addr) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *Inet6Addr) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *Inet6Addr) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SockAddrInet6) SizeBytes() int {
    return 12 +
        1*16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrInet6) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Port))
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Flowinfo))
    dst = dst[4:]
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(s.Addr[idx])
        dst = dst[1:]
    }
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Scope_id))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrInet6) UnmarshalBytes(src []byte) {
    s.Family = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Port = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Flowinfo = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 16; idx++ {
        s.Addr[idx] = src[0]
        src = src[1:]
    }
    s.Scope_id = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrInet6) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrInet6) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrInet6) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SockAddrInet6) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SockAddrInet6) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SockAddrInet6) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrInet6) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SockAddrLink) SizeBytes() int {
    return 12 +
        1*8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrLink) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Protocol))
    dst = dst[2:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.InterfaceIndex))
    dst = dst[4:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.ARPHardwareType))
    dst = dst[2:]
    dst[0] = byte(s.PacketType)
    dst = dst[1:]
    dst[0] = byte(s.HardwareAddrLen)
    dst = dst[1:]
    for idx := 0; idx < 8; idx++ {
        dst[0] = byte(s.HardwareAddr[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrLink) UnmarshalBytes(src []byte) {
    s.Family = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Protocol = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.InterfaceIndex = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.ARPHardwareType = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.PacketType = src[0]
    src = src[1:]
    s.HardwareAddrLen = src[0]
    src = src[1:]
    for idx := 0; idx < 8; idx++ {
        s.HardwareAddr[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrLink) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrLink) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrLink) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SockAddrLink) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SockAddrLink) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SockAddrLink) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrLink) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SockAddrUnix) SizeBytes() int {
    return 2 +
        1*UnixPathMax
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SockAddrUnix) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    for idx := 0; idx < UnixPathMax; idx++ {
        dst[0] = byte(s.Path[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SockAddrUnix) UnmarshalBytes(src []byte) {
    s.Family = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < UnixPathMax; idx++ {
        s.Path[idx] = int8(src[0])
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrUnix) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *SockAddrUnix) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *SockAddrUnix) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *SockAddrUnix) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *SockAddrUnix) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *SockAddrUnix) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *SockAddrUnix) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (l *Linger) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (l *Linger) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(l.OnOff))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(l.Linger))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (l *Linger) UnmarshalBytes(src []byte) {
    l.OnOff = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    l.Linger = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (l *Linger) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (l *Linger) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(l))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (l *Linger) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(l), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (l *Linger) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (l *Linger) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return l.CopyOutN(cc, addr, l.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (l *Linger) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (l *Linger) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that l
    // must live until the use above.
    runtime.KeepAlive(l) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *TCPInfo) SizeBytes() int {
    return 192
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *TCPInfo) MarshalBytes(dst []byte) {
    dst[0] = byte(t.State)
    dst = dst[1:]
    dst[0] = byte(t.CaState)
    dst = dst[1:]
    dst[0] = byte(t.Retransmits)
    dst = dst[1:]
    dst[0] = byte(t.Probes)
    dst = dst[1:]
    dst[0] = byte(t.Backoff)
    dst = dst[1:]
    dst[0] = byte(t.Options)
    dst = dst[1:]
    dst[0] = byte(t.WindowScale)
    dst = dst[1:]
    dst[0] = byte(t.DeliveryRateAppLimited)
    dst = dst[1:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RTO))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.ATO))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SndMss))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RcvMss))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Unacked))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Sacked))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Lost))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Retrans))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Fackets))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LastDataSent))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LastAckSent))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LastDataRecv))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LastAckRecv))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.PMTU))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RcvSsthresh))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RTT))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RTTVar))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SndSsthresh))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SndCwnd))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Advmss))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.Reordering))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RcvRTT))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.RcvSpace))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.TotalRetrans))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.PacingRate))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.MaxPacingRate))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.BytesAcked))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.BytesReceived))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SegsOut))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.SegsIn))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.NotSentBytes))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.MinRTT))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.DataSegsIn))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.DataSegsOut))
    dst = dst[4:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.DeliveryRate))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.BusyTime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.RwndLimited))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.SndBufLimited))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *TCPInfo) UnmarshalBytes(src []byte) {
    t.State = uint8(src[0])
    src = src[1:]
    t.CaState = uint8(src[0])
    src = src[1:]
    t.Retransmits = uint8(src[0])
    src = src[1:]
    t.Probes = uint8(src[0])
    src = src[1:]
    t.Backoff = uint8(src[0])
    src = src[1:]
    t.Options = uint8(src[0])
    src = src[1:]
    t.WindowScale = uint8(src[0])
    src = src[1:]
    t.DeliveryRateAppLimited = uint8(src[0])
    src = src[1:]
    t.RTO = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ATO = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndMss = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvMss = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Unacked = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Sacked = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Lost = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Retrans = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Fackets = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastDataSent = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastAckSent = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastDataRecv = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastAckRecv = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.PMTU = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvSsthresh = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RTT = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RTTVar = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndSsthresh = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndCwnd = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Advmss = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Reordering = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvRTT = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvSpace = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TotalRetrans = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.PacingRate = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.MaxPacingRate = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesAcked = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesReceived = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.SegsOut = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SegsIn = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.NotSentBytes = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.MinRTT = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DataSegsIn = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DataSegsOut = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DeliveryRate = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BusyTime = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.RwndLimited = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.SndBufLimited = uint64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TCPInfo) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *TCPInfo) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *TCPInfo) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *TCPInfo) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *TCPInfo) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *TCPInfo) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *TCPInfo) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (c *ControlMessageCredentials) SizeBytes() int {
    return 12
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ControlMessageCredentials) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.PID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.UID))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(c.GID))
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ControlMessageCredentials) UnmarshalBytes(src []byte) {
    c.PID = int32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.UID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.GID = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageCredentials) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ControlMessageCredentials) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(c))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ControlMessageCredentials) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(c), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (c *ControlMessageCredentials) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (c *ControlMessageCredentials) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (c *ControlMessageCredentials) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ControlMessageCredentials) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (t *TimeT) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *TimeT) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(*t))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *TimeT) UnmarshalBytes(src []byte) {
    *t = TimeT(int64(usermem.ByteOrder.Uint64(src[:8])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TimeT) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *TimeT) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *TimeT) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *TimeT) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *TimeT) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *TimeT) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *TimeT) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *Timespec) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *Timespec) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.Sec))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.Nsec))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *Timespec) UnmarshalBytes(src []byte) {
    t.Sec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.Nsec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Timespec) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *Timespec) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *Timespec) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *Timespec) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *Timespec) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *Timespec) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Timespec) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyTimespecSliceIn copies in a slice of Timespec objects from the task's memory.
func CopyTimespecSliceIn(cc marshal.CopyContext, addr usermem.Addr, dst []Timespec) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyTimespecSliceOut copies a slice of Timespec objects to the task's memory.
func CopyTimespecSliceOut(cc marshal.CopyContext, addr usermem.Addr, src []Timespec) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeTimespecSlice is like Timespec.MarshalUnsafe, but for a []Timespec.
func MarshalUnsafeTimespecSlice(src []Timespec, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyIn(dst[:(size*count)], val)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// UnmarshalUnsafeTimespecSlice is like Timespec.UnmarshalUnsafe, but for a []Timespec.
func UnmarshalUnsafeTimespecSlice(dst []Timespec, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyOut(val, src[:(size*count)])
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *Timeval) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *Timeval) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.Sec))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(t.Usec))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *Timeval) UnmarshalBytes(src []byte) {
    t.Sec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.Usec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Timeval) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *Timeval) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *Timeval) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *Timeval) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *Timeval) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *Timeval) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Timeval) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// CopyTimevalSliceIn copies in a slice of Timeval objects from the task's memory.
func CopyTimevalSliceIn(cc marshal.CopyContext, addr usermem.Addr, dst []Timeval) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// CopyTimevalSliceOut copies a slice of Timeval objects to the task's memory.
func CopyTimevalSliceOut(cc marshal.CopyContext, addr usermem.Addr, src []Timeval) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// MarshalUnsafeTimevalSlice is like Timeval.MarshalUnsafe, but for a []Timeval.
func MarshalUnsafeTimevalSlice(src []Timeval, dst []byte) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyIn(dst[:(size*count)], val)
    // Since we bypassed the compiler's escape analysis, indicate that src
    // must live until the use above.
    runtime.KeepAlive(src) // escapes: replaced by intrinsic.
    return length, err
}

// UnmarshalUnsafeTimevalSlice is like Timeval.UnmarshalUnsafe, but for a []Timeval.
func UnmarshalUnsafeTimevalSlice(dst []Timeval, src []byte) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    length, err := safecopy.CopyOut(val, src[:(size*count)])
    // Since we bypassed the compiler's escape analysis, indicate that dst
    // must live until the use above.
    runtime.KeepAlive(dst) // escapes: replaced by intrinsic.
    return length, err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *Itimerspec) SizeBytes() int {
    return 0 +
        (*Timespec)(nil).SizeBytes() +
        (*Timespec)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *Itimerspec) MarshalBytes(dst []byte) {
    i.Interval.MarshalBytes(dst[:i.Interval.SizeBytes()])
    dst = dst[i.Interval.SizeBytes():]
    i.Value.MarshalBytes(dst[:i.Value.SizeBytes()])
    dst = dst[i.Value.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *Itimerspec) UnmarshalBytes(src []byte) {
    i.Interval.UnmarshalBytes(src[:i.Interval.SizeBytes()])
    src = src[i.Interval.SizeBytes():]
    i.Value.UnmarshalBytes(src[:i.Value.SizeBytes()])
    src = src[i.Value.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Itimerspec) Packed() bool {
    return i.Interval.Packed() && i.Value.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *Itimerspec) MarshalUnsafe(dst []byte) {
    if i.Interval.Packed() && i.Value.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type Itimerspec doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *Itimerspec) UnmarshalUnsafe(src []byte) {
    if i.Interval.Packed() && i.Value.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type Itimerspec doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *Itimerspec) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type Itimerspec doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *Itimerspec) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *Itimerspec) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type Itimerspec doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *Itimerspec) WriteTo(writer io.Writer) (int64, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type Itimerspec doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (i *ItimerVal) SizeBytes() int {
    return 0 +
        (*Timeval)(nil).SizeBytes() +
        (*Timeval)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (i *ItimerVal) MarshalBytes(dst []byte) {
    i.Interval.MarshalBytes(dst[:i.Interval.SizeBytes()])
    dst = dst[i.Interval.SizeBytes():]
    i.Value.MarshalBytes(dst[:i.Value.SizeBytes()])
    dst = dst[i.Value.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (i *ItimerVal) UnmarshalBytes(src []byte) {
    i.Interval.UnmarshalBytes(src[:i.Interval.SizeBytes()])
    src = src[i.Interval.SizeBytes():]
    i.Value.UnmarshalBytes(src[:i.Value.SizeBytes()])
    src = src[i.Value.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *ItimerVal) Packed() bool {
    return i.Interval.Packed() && i.Value.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (i *ItimerVal) MarshalUnsafe(dst []byte) {
    if i.Interval.Packed() && i.Value.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(i))
    } else {
        // Type ItimerVal doesn't have a packed layout in memory, fallback to MarshalBytes.
        i.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (i *ItimerVal) UnmarshalUnsafe(src []byte) {
    if i.Interval.Packed() && i.Value.Packed() {
        safecopy.CopyOut(unsafe.Pointer(i), src)
    } else {
        // Type ItimerVal doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        i.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (i *ItimerVal) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type ItimerVal doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        i.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (i *ItimerVal) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (i *ItimerVal) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type ItimerVal doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(i.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        i.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (i *ItimerVal) WriteTo(writer io.Writer) (int64, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
        // Type ItimerVal doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that i
    // must live until the use above.
    runtime.KeepAlive(i) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (c *ClockT) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (c *ClockT) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(*c))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (c *ClockT) UnmarshalBytes(src []byte) {
    *c = ClockT(int64(usermem.ByteOrder.Uint64(src[:8])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ClockT) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (c *ClockT) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(c))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (c *ClockT) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(c), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (c *ClockT) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (c *ClockT) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (c *ClockT) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (c *ClockT) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that c
    // must live until the use above.
    runtime.KeepAlive(c) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *Tms) SizeBytes() int {
    return 0 +
        (*ClockT)(nil).SizeBytes() +
        (*ClockT)(nil).SizeBytes() +
        (*ClockT)(nil).SizeBytes() +
        (*ClockT)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *Tms) MarshalBytes(dst []byte) {
    t.UTime.MarshalBytes(dst[:t.UTime.SizeBytes()])
    dst = dst[t.UTime.SizeBytes():]
    t.STime.MarshalBytes(dst[:t.STime.SizeBytes()])
    dst = dst[t.STime.SizeBytes():]
    t.CUTime.MarshalBytes(dst[:t.CUTime.SizeBytes()])
    dst = dst[t.CUTime.SizeBytes():]
    t.CSTime.MarshalBytes(dst[:t.CSTime.SizeBytes()])
    dst = dst[t.CSTime.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *Tms) UnmarshalBytes(src []byte) {
    t.UTime.UnmarshalBytes(src[:t.UTime.SizeBytes()])
    src = src[t.UTime.SizeBytes():]
    t.STime.UnmarshalBytes(src[:t.STime.SizeBytes()])
    src = src[t.STime.SizeBytes():]
    t.CUTime.UnmarshalBytes(src[:t.CUTime.SizeBytes()])
    src = src[t.CUTime.SizeBytes():]
    t.CSTime.UnmarshalBytes(src[:t.CSTime.SizeBytes()])
    src = src[t.CSTime.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Tms) Packed() bool {
    return t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *Tms) MarshalUnsafe(dst []byte) {
    if t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        safecopy.CopyIn(dst, unsafe.Pointer(t))
    } else {
        // Type Tms doesn't have a packed layout in memory, fallback to MarshalBytes.
        t.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *Tms) UnmarshalUnsafe(src []byte) {
    if t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        safecopy.CopyOut(unsafe.Pointer(t), src)
    } else {
        // Type Tms doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        t.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *Tms) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    if !t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        // Type Tms doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(t.SizeBytes()) // escapes: okay.
        t.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *Tms) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *Tms) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    if !t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        // Type Tms doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(t.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        t.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Tms) WriteTo(writer io.Writer) (int64, error) {
    if !t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        // Type Tms doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, t.SizeBytes())
        t.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (t *TimerID) SizeBytes() int {
    return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *TimerID) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(*t))
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *TimerID) UnmarshalBytes(src []byte) {
    *t = TimerID(int32(usermem.ByteOrder.Uint32(src[:4])))
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TimerID) Packed() bool {
    // Scalar newtypes are always packed.
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *TimerID) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *TimerID) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *TimerID) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *TimerID) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *TimerID) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *TimerID) WriteTo(w io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := w.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *StatxTimestamp) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *StatxTimestamp) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(s.Sec))
    dst = dst[8:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(s.Nsec))
    dst = dst[4:]
    // Padding: dst[:sizeof(int32)] ~= int32(0)
    dst = dst[4:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *StatxTimestamp) UnmarshalBytes(src []byte) {
    s.Sec = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Nsec = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    // Padding: var _ int32 ~= src[:sizeof(int32)]
    src = src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *StatxTimestamp) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (s *StatxTimestamp) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(s))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (s *StatxTimestamp) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(s), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *StatxTimestamp) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (s *StatxTimestamp) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (s *StatxTimestamp) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (s *StatxTimestamp) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that s
    // must live until the use above.
    runtime.KeepAlive(s) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *Utime) SizeBytes() int {
    return 16
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *Utime) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint64(dst[:8], uint64(u.Actime))
    dst = dst[8:]
    usermem.ByteOrder.PutUint64(dst[:8], uint64(u.Modtime))
    dst = dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *Utime) UnmarshalBytes(src []byte) {
    u.Actime = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Modtime = int64(usermem.ByteOrder.Uint64(src[:8]))
    src = src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *Utime) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *Utime) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(u))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *Utime) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(u), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (u *Utime) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (u *Utime) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (u *Utime) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *Utime) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *Winsize) SizeBytes() int {
    return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *Winsize) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Row))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Col))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Xpixel))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Ypixel))
    dst = dst[2:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *Winsize) UnmarshalBytes(src []byte) {
    w.Row = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Col = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Xpixel = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Ypixel = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (w *Winsize) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (w *Winsize) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(w))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (w *Winsize) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(w), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (w *Winsize) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (w *Winsize) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return w.CopyOutN(cc, addr, w.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (w *Winsize) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (w *Winsize) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *Termios) SizeBytes() int {
    return 17 +
        1*NumControlCharacters
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *Termios) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.InputFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.OutputFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.ControlFlags))
    dst = dst[4:]
    usermem.ByteOrder.PutUint32(dst[:4], uint32(t.LocalFlags))
    dst = dst[4:]
    dst[0] = byte(t.LineDiscipline)
    dst = dst[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        dst[0] = byte(t.ControlCharacters[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *Termios) UnmarshalBytes(src []byte) {
    t.InputFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.OutputFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ControlFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LocalFlags = uint32(usermem.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LineDiscipline = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        t.ControlCharacters[idx] = uint8(src[0])
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Termios) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *Termios) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(t))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *Termios) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(t), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (t *Termios) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (t *Termios) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (t *Termios) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *Termios) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that t
    // must live until the use above.
    runtime.KeepAlive(t) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (w *WindowSize) SizeBytes() int {
    return 4 +
        1*4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (w *WindowSize) MarshalBytes(dst []byte) {
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Rows))
    dst = dst[2:]
    usermem.ByteOrder.PutUint16(dst[:2], uint16(w.Cols))
    dst = dst[2:]
    // Padding: dst[:sizeof(byte)*4] ~= [4]byte{0}
    dst = dst[1*(4):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (w *WindowSize) UnmarshalBytes(src []byte) {
    w.Rows = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Cols = uint16(usermem.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    // Padding: ~ copy([4]byte(w._), src[:sizeof(byte)*4])
    src = src[1*(4):]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (w *WindowSize) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (w *WindowSize) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(w))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (w *WindowSize) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(w), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (w *WindowSize) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (w *WindowSize) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return w.CopyOutN(cc, addr, w.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (w *WindowSize) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (w *WindowSize) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that w
    // must live until the use above.
    runtime.KeepAlive(w) // escapes: replaced by intrinsic.
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (u *UtsName) SizeBytes() int {
    return 0 +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (u *UtsName) MarshalBytes(dst []byte) {
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Sysname[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Nodename[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Release[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Version[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Machine[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Domainname[idx])
        dst = dst[1:]
    }
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (u *UtsName) UnmarshalBytes(src []byte) {
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Sysname[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Nodename[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Release[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Version[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Machine[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Domainname[idx] = src[0]
        src = src[1:]
    }
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UtsName) Packed() bool {
    return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (u *UtsName) MarshalUnsafe(dst []byte) {
    safecopy.CopyIn(dst, unsafe.Pointer(u))
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (u *UtsName) UnmarshalUnsafe(src []byte) {
    safecopy.CopyOut(unsafe.Pointer(u), src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (u *UtsName) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// CopyOut implements marshal.Marshallable.CopyOut.
//go:nosplit
func (u *UtsName) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (u *UtsName) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return length, err
}

// WriteTo implements io.WriterTo.WriteTo.
func (u *UtsName) WriteTo(writer io.Writer) (int64, error) {
    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that u
    // must live until the use above.
    runtime.KeepAlive(u) // escapes: replaced by intrinsic.
    return int64(length), err
}

