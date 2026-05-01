//go:build windows

package technique

import "unsafe"

// CONTEXT x64 — raw byte array matching winnt.h CONTEXT for AMD64.
// Total size: 1232 bytes (0x4D0).
//
// Key offsets:
//   0x30 (48)  : ContextFlags (uint32)
//   0xF8 (248) : Rip (uint64)
type CONTEXT [1232]byte

func (c *CONTEXT) SetFlags(flags uint32) {
	*(*uint32)(unsafe.Pointer(&c[48])) = flags
}

func (c *CONTEXT) GetRip() uint64 {
	return *(*uint64)(unsafe.Pointer(&c[248]))
}

func (c *CONTEXT) SetRip(v uint64) {
	*(*uint64)(unsafe.Pointer(&c[248])) = v
}

// alignedContext holds a CONTEXT with a guaranteed 16-byte aligned pointer.
// GetThreadContext / SetThreadContext return ERROR_INVALID_PARAMETER on misaligned
// pointers. Go's allocator provides 8-byte alignment for heap objects, which is
// insufficient. We over-allocate by 15 bytes and align manually.
//
// The buf field must remain live for as long as ctx is in use — keeping both
// fields in the same struct ensures the GC doesn't collect buf early.
type alignedContext struct {
	ctx *CONTEXT
	buf []byte // backing allocation — must stay alive
}

func newAlignedContext() *alignedContext {
	buf := make([]byte, 1232+16)
	addr := (uintptr(unsafe.Pointer(&buf[0])) + 15) &^ 15
	return &alignedContext{
		ctx: (*CONTEXT)(unsafe.Pointer(addr)),
		buf: buf,
	}
}
