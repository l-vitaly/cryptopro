package cryptopro

//#cgo 386 darwin LDFLAGS: -L/opt/cprocsp/lib/ -lcapi10 -lcapi20 -lrdrsup -lssp
//#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lrdrsup -lssp
//#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lrdrsup -lssp
//#cgo windows LDFLAGS: -lcrypt32 -lpthread
//#include "common.h"
import "C"
import "unsafe"

func charPtr(s string) *C.CHAR {
	if s != "" {
		return (*C.CHAR)(unsafe.Pointer(C.CString(s)))
	}
	return nil
}

func freePtr(s *C.CHAR) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}
