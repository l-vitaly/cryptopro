package cryptopro

//#cgo linux,386 darwin CFLAGS: -I/opt/cprocsp/include/cpcsp
//#cgo linux,amd64,386 darwin LDFLAGS: -L/opt/cprocsp/lib/ -lcapi10 -lcapi20 -lrdrsup -lssp
//#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lrdrsup -lssp
//#cgo windows LDFLAGS: -lcrypt32 -lpthread
//#include "common.h"
import "C"
import (
	"unsafe"

	"github.com/pkg/errors"
)

var (
	ErrCreatingCertificateCtx = errors.New("error a new certificate could not be created")
    ErrVerifyingSignature = errors.New("error verifying message signature")
)

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
