//go:build !windows

package technique

import "fmt"

func ClassicInject(target string, shellcode []byte) error {
	return fmt.Errorf("ClassicInject: windows only")
}

func SectionInject(target string, shellcode []byte) error {
	return fmt.Errorf("SectionInject: windows only")
}

func APCInject(target string, shellcode []byte) error {
	return fmt.Errorf("APCInject: windows only")
}

func HijackInject(target string, shellcode []byte) error {
	return fmt.Errorf("HijackInject: windows only")
}

func StompInject(target string, shellcode []byte) error {
	return fmt.Errorf("StompInject: windows only")
}

func DirectSyscallInject(target string, shellcode []byte) error {
	return fmt.Errorf("DirectSyscallInject: windows only")
}
