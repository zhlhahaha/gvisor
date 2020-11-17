package proc

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/refsvfs2"
)

// enableLogging indicates whether reference-related events should be logged (with
// stack traces). This is false by default and should only be set to true for
// debugging purposes, as it can generate an extremely large amount of output
// and drastically degrade performance.
const fdInfoDirInodeenableLogging = false

// obj is used to customize logging. Note that we use a pointer to T so that
// we do not copy the entire object when passed as a format parameter.
var fdInfoDirInodeobj *fdInfoDirInode

// Refs implements refs.RefCounter. It keeps a reference count using atomic
// operations and calls the destructor when the count reaches zero.
//
// +stateify savable
type fdInfoDirInodeRefs struct {
	// refCount is composed of two fields:
	//
	//	[32-bit speculative references]:[32-bit real references]
	//
	// Speculative references are used for TryIncRef, to avoid a CompareAndSwap
	// loop. See IncRef, DecRef and TryIncRef for details of how these fields are
	// used.
	refCount int64
}

// InitRefs initializes r with one reference and, if enabled, activates leak
// checking.
func (r *fdInfoDirInodeRefs) InitRefs() {
	atomic.StoreInt64(&r.refCount, 1)
	refsvfs2.Register(r)
}

// RefType implements refsvfs2.CheckedObject.RefType.
func (r *fdInfoDirInodeRefs) RefType() string {
	return fmt.Sprintf("%T", fdInfoDirInodeobj)[1:]
}

// LeakMessage implements refsvfs2.CheckedObject.LeakMessage.
func (r *fdInfoDirInodeRefs) LeakMessage() string {
	return fmt.Sprintf("[%s %p] reference count of %d instead of 0", r.RefType(), r, r.ReadRefs())
}

// LogRefs implements refsvfs2.CheckedObject.LogRefs.
func (r *fdInfoDirInodeRefs) LogRefs() bool {
	return fdInfoDirInodeenableLogging
}

// EnableLeakCheck enables reference leak checking on r.
func (r *fdInfoDirInodeRefs) EnableLeakCheck() {
	refsvfs2.Register(r)
}

// ReadRefs returns the current number of references. The returned count is
// inherently racy and is unsafe to use without external synchronization.
func (r *fdInfoDirInodeRefs) ReadRefs() int64 {
	return atomic.LoadInt64(&r.refCount)
}

// IncRef implements refs.RefCounter.IncRef.
//
//go:nosplit
func (r *fdInfoDirInodeRefs) IncRef() {
	v := atomic.AddInt64(&r.refCount, 1)
	if fdInfoDirInodeenableLogging {
		refsvfs2.LogIncRef(r, v)
	}
	if v <= 1 {
		panic(fmt.Sprintf("Incrementing non-positive count %p on %s", r, r.RefType()))
	}
}

// TryIncRef implements refs.RefCounter.TryIncRef.
//
// To do this safely without a loop, a speculative reference is first acquired
// on the object. This allows multiple concurrent TryIncRef calls to distinguish
// other TryIncRef calls from genuine references held.
//
//go:nosplit
func (r *fdInfoDirInodeRefs) TryIncRef() bool {
	const speculativeRef = 1 << 32
	if v := atomic.AddInt64(&r.refCount, speculativeRef); int32(v) == 0 {

		atomic.AddInt64(&r.refCount, -speculativeRef)
		return false
	}

	v := atomic.AddInt64(&r.refCount, -speculativeRef+1)
	if fdInfoDirInodeenableLogging {
		refsvfs2.LogTryIncRef(r, v)
	}
	return true
}

// DecRef implements refs.RefCounter.DecRef.
//
// Note that speculative references are counted here. Since they were added
// prior to real references reaching zero, they will successfully convert to
// real references. In other words, we see speculative references only in the
// following case:
//
//	A: TryIncRef [speculative increase => sees non-negative references]
//	B: DecRef [real decrease]
//	A: TryIncRef [transform speculative to real]
//
//go:nosplit
func (r *fdInfoDirInodeRefs) DecRef(destroy func()) {
	v := atomic.AddInt64(&r.refCount, -1)
	if fdInfoDirInodeenableLogging {
		refsvfs2.LogDecRef(r, v+1)
	}
	switch {
	case v < 0:
		panic(fmt.Sprintf("Decrementing non-positive ref count %p, owned by %s", r, r.RefType()))

	case v == 0:
		refsvfs2.Unregister(r)

		if destroy != nil {
			destroy()
		}
	}
}

func (r *fdInfoDirInodeRefs) afterLoad() {
	if r.ReadRefs() > 0 {
		r.EnableLeakCheck()
	}
}
