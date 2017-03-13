package cryptopro

//#include "common.h"
import "C"

import (
	"unsafe"

	"github.com/pkg/errors"
)

type CryptFlag C.DWORD
type ProvType C.DWORD

const (
	CryptVerifyContext CryptFlag = C.CRYPT_VERIFYCONTEXT
	CryptNewKeyset     CryptFlag = C.CRYPT_NEWKEYSET
	CryptMachineKeyset CryptFlag = C.CRYPT_MACHINE_KEYSET
	CryptDeleteKeyset  CryptFlag = C.CRYPT_DELETEKEYSET
	CryptSilent        CryptFlag = C.CRYPT_SILENT
)

const (
	ProvRsa      ProvType = C.PROV_RSA_FULL
	ProvGost94   ProvType = 71
	ProvGost2001 ProvType = 75
)

var (
	ErrDuringProviderEnum   = errors.New("error during provider enumeration")
	ErfAcquiringCtx         = errors.New("error acquiring context")
	ErrReleaseCtx           = errors.New("error releasing context")
	ErrSetContainerPassword = errors.New("error setting container password")
)

type Ctx struct {
	hProv C.HCRYPTPROV
}

type CryptoProvider struct {
	Name string
	Type ProvType
}

func EnumProviders() ([]CryptoProvider, error) {
	var (
		slen, provType, index C.DWORD
	)

	res := make([]CryptoProvider, 0)

	for index = 0; C.CryptEnumProviders(index, nil, 0, &provType, nil, &slen) != 0; index++ {
		buf := make([]byte, slen)
		if C.CryptEnumProviders(index, nil, 0, &provType, (*C.CHAR)(unsafe.Pointer(&buf[0])), &slen) == 0 {
			return nil, ErrDuringProviderEnum
		}
		res = append(res, CryptoProvider{Name: string(buf), Type: ProvType(provType)})
	}
	return res, nil
}

func AcquireCtx(container, provider string, provType ProvType, flags CryptFlag) (Ctx, error) {
	cContainer := charPtr(container)
	defer freePtr(cContainer)
	cProvider := charPtr(provider)
	defer freePtr(cProvider)

	res := Ctx{}
	if C.CryptAcquireContext(&res.hProv, cContainer, cProvider, C.DWORD(provType), C.DWORD(flags)) == 0 {
		return res, ErfAcquiringCtx
	}
	return res, nil
}

func DeleteCtx(container, provider string, provType ProvType) error {
	_, err := AcquireCtx(container, provider, provType, CryptDeleteKeyset)
	return err
}

func (ctx Ctx) Close() error {
	if C.CryptReleaseContext(ctx.hProv, 0) == 0 {
		return ErrReleaseCtx
	}
	return nil
}

func (ctx Ctx) SetPassword(pwd string, at KeyPairId) error {
	var pParam C.DWORD
	pin := unsafe.Pointer(C.CString(pwd))
	defer C.free(pin)

	if at == AtSignature {
		pParam = C.PP_SIGNATURE_PIN
	} else {
		pParam = C.PP_KEYEXCHANGE_PIN
	}
	if C.CryptSetProvParam(ctx.hProv, pParam, (*C.BYTE)(pin), 0) == 0 {
		return ErrSetContainerPassword
	}
	return nil
}
