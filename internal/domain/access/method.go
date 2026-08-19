package access

import "errors"

type MethodCategory uint8

const (
	CategoryUnknown MethodCategory = iota
	CategoryNone
	CategoryStream
	CategoryAEAD
	CategoryAEAD2022
)

func (c MethodCategory) String() string {
	switch c {
	case CategoryNone:
		return "none"
	case CategoryStream:
		return "stream"
	case CategoryAEAD:
		return "aead"
	case CategoryAEAD2022:
		return "aead2022"
	default:
		return "unknown"
	}
}

type Method string

const (
	// CategoryNone
	MethodNone Method = "none"
	// CategoryStream
	MethodAES128CTR    Method = "aes-128-ctr"
	MethodAES192CTR    Method = "aes-192-ctr"
	MethodAES256CTR    Method = "aes-256-ctr"
	MethodAES128CFB    Method = "aes-128-cfb"
	MethodAES192CFB    Method = "aes-192-cfb"
	MethodAES256CFB    Method = "aes-256-cfb"
	MethodRC4MD5       Method = "rc4-md5"
	MethodChaCha20IETF Method = "chacha20-ietf"
	MethodXChaCha20    Method = "xchacha20"
	// CategoryAEAD
	MethodAES128GCM             Method = "aes-128-gcm"
	MethodAES192GCM             Method = "aes-192-gcm"
	MethodAES256GCM             Method = "aes-256-gcm"
	MethodChaCha20IETFPoly1305  Method = "chacha20-ietf-poly1305"
	MethodXChaCha20IETFPoly1305 Method = "xchacha20-ietf-poly1305"
	// CategoryAEAD2022
	Method2022Blake3AES128GCM        Method = "2022-blake3-aes-128-gcm"
	Method2022Blake3AES256GCM        Method = "2022-blake3-aes-256-gcm"
	Method2022Blake3ChaCha20Poly1305 Method = "2022-blake3-chacha20-poly1305"
)

var (
	ErrUnsupportedMethod = errors.New("unsupported method")
)

func (m Method) IsKnown() bool {
	switch m {
	case MethodNone,
		MethodAES128CTR,
		MethodAES192CTR,
		MethodAES256CTR,
		MethodAES128CFB,
		MethodAES192CFB,
		MethodAES256CFB,
		MethodRC4MD5,
		MethodChaCha20IETF,
		MethodXChaCha20,
		MethodAES128GCM,
		MethodAES192GCM,
		MethodAES256GCM,
		MethodChaCha20IETFPoly1305,
		MethodXChaCha20IETFPoly1305,
		Method2022Blake3AES128GCM,
		Method2022Blake3AES256GCM,
		Method2022Blake3ChaCha20Poly1305:
		return true
	default:
		return false
	}
}

func (m Method) Category() MethodCategory {
	switch m {
	case MethodNone:
		return CategoryNone
	case MethodAES128CTR,
		MethodAES192CTR,
		MethodAES256CTR,
		MethodAES128CFB,
		MethodAES192CFB,
		MethodAES256CFB,
		MethodRC4MD5,
		MethodChaCha20IETF,
		MethodXChaCha20:
		return CategoryStream
	case MethodAES128GCM,
		MethodAES192GCM,
		MethodAES256GCM,
		MethodChaCha20IETFPoly1305,
		MethodXChaCha20IETFPoly1305:
		return CategoryAEAD
	case Method2022Blake3AES128GCM,
		Method2022Blake3AES256GCM,
		Method2022Blake3ChaCha20Poly1305:
		return CategoryAEAD2022
	default:
		return CategoryUnknown
	}
}
