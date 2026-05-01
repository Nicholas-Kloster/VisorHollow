//go:build windows

package technique

import "unsafe"

// CONTEXT x64 — raw byte array layout matching winnt.h CONTEXT for AMD64.
// Total size: 1232 bytes (0x4D0). Must be 16-byte aligned for Get/SetThreadContext.
//
// Key offsets:
//   0x30 (48)  : ContextFlags (uint32)
//   0x34 (52)  : MxCsr (uint32)
//   0xF8 (248) : Rip (uint64)
//   0x98 (152) : Rsp (uint64)
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
