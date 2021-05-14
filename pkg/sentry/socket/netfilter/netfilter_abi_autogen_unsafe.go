// Automatically generated marshal implementation. See tools/go_marshal.

// If there are issues with build tag aggregation, see
// tools/go_marshal/gomarshal/generator.go:writeHeader(). The build tags here
// come from the input set of files used to generate this file. This input set
// is filtered based on pre-defined file suffixes related to build tags, see 
// tools/defs.bzl:calculate_sets().

package netfilter

import (
    "gvisor.dev/gvisor/pkg/abi/linux"
    "gvisor.dev/gvisor/pkg/gohacks"
    "gvisor.dev/gvisor/pkg/hostarch"
    "gvisor.dev/gvisor/pkg/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

// Marshallable types used by this file.
var _ marshal.Marshallable = (*linux.NFNATRange)(nil)
var _ marshal.Marshallable = (*linux.XTEntryTarget)(nil)
var _ marshal.Marshallable = (*nfNATTarget)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (n *nfNATTarget) SizeBytes() int {
    return 0 +
        (*linux.XTEntryTarget)(nil).SizeBytes() +
        (*linux.NFNATRange)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (n *nfNATTarget) MarshalBytes(dst []byte) {
    n.Target.MarshalBytes(dst[:n.Target.SizeBytes()])
    dst = dst[n.Target.SizeBytes():]
    n.Range.MarshalBytes(dst[:n.Range.SizeBytes()])
    dst = dst[n.Range.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (n *nfNATTarget) UnmarshalBytes(src []byte) {
    n.Target.UnmarshalBytes(src[:n.Target.SizeBytes()])
    src = src[n.Target.SizeBytes():]
    n.Range.UnmarshalBytes(src[:n.Range.SizeBytes()])
    src = src[n.Range.SizeBytes():]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *nfNATTarget) Packed() bool {
    return n.Range.Packed() && n.Target.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (n *nfNATTarget) MarshalUnsafe(dst []byte) {
    if n.Range.Packed() && n.Target.Packed() {
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n),  uintptr(n.SizeBytes()))
    } else {
        // Type nfNATTarget doesn't have a packed layout in memory, fallback to MarshalBytes.
        n.MarshalBytes(dst)
    }
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (n *nfNATTarget) UnmarshalUnsafe(src []byte) {
    if n.Range.Packed() && n.Target.Packed() {
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(n.SizeBytes()))
    } else {
        // Type nfNATTarget doesn't have a packed layout in memory, fallback to UnmarshalBytes.
        n.UnmarshalBytes(src)
    }
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (n *nfNATTarget) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Range.Packed() && n.Target.Packed() {
        // Type nfNATTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        n.MarshalBytes(buf) // escapes: fallback.
        return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.
    }

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
func (n *nfNATTarget) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

// CopyIn implements marshal.Marshallable.CopyIn.
//go:nosplit
func (n *nfNATTarget) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    if !n.Range.Packed() && n.Target.Packed() {
        // Type nfNATTarget doesn't have a packed layout in memory, fall back to UnmarshalBytes.
        buf := cc.CopyScratchBuffer(n.SizeBytes()) // escapes: okay.
        length, err := cc.CopyInBytes(addr, buf) // escapes: okay.
        // Unmarshal unconditionally. If we had a short copy-in, this results in a
        // partially unmarshalled struct.
        n.UnmarshalBytes(buf) // escapes: fallback.
        return length, err
    }

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
func (n *nfNATTarget) WriteTo(writer io.Writer) (int64, error) {
    if !n.Range.Packed() && n.Target.Packed() {
        // Type nfNATTarget doesn't have a packed layout in memory, fall back to MarshalBytes.
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    // Construct a slice backed by dst's underlying memory.
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    // Since we bypassed the compiler's escape analysis, indicate that n
    // must live until the use above.
    runtime.KeepAlive(n) // escapes: replaced by intrinsic.
    return int64(length), err
}

