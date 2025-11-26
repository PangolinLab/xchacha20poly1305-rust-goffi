package xchacha20_poly1305_ffi

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"unsafe"
)

/*
	#cgo CFLAGS: -I${SRCDIR}/include
	#cgo LDFLAGS: -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp -L${SRCDIR}/bin -lxchacha20_poly1305
	#include "xchacha20_poly1305_interface.h"
*/
import "C"

const (
	KeyLength   = 32
	NonceLength = 24
	TagLength   = 16
)

func init() {
    // 动态库最终路径
    var libFile string
    switch runtime.GOOS {
    case "windows":
        libFile = "bin/xchacha20_poly1305.dll"
    case "darwin":
        libFile = "bin/libxchacha20_poly1305.dylib"
    default:
        libFile = "bin/libxchacha20_poly1305.so"
    }

    // 如果库不存在，则编译 Rust 并复制到 bin/
    if _, err := os.Stat(libFile); os.IsNotExist(err) {
        // Rust 源码目录（Cargo.toml 所在目录）
        rustDir := "../" // 根据你的目录结构调整
        buildCmd := exec.Command("cargo", "build", "--release")
        buildCmd.Dir = rustDir
        buildCmd.Stdout = os.Stdout
        buildCmd.Stderr = os.Stderr
        if err := buildCmd.Run(); err != nil {
            panic("Failed to build Rust library: " + err.Error())
        }

        // 源文件路径（默认 target/release/）
        var srcLib string
        switch runtime.GOOS {
        case "windows":
            srcLib = filepath.Join(rustDir, "target", "release", "xchacha20_poly1305.dll")
        case "darwin":
            srcLib = filepath.Join(rustDir, "target", "release", "libxchacha20_poly1305.dylib")
        default:
            srcLib = filepath.Join(rustDir, "target", "release", "libxchacha20_poly1305.so")
        }

        // 确保 bin 目录存在
        _ = os.MkdirAll("bin", 0755)

        // 复制库到 bin/
        input, err := os.ReadFile(srcLib)
        if err != nil {
            panic("Failed to read Rust library: " + err.Error())
        }
        if err := os.WriteFile(libFile, input, 0644); err != nil {
            panic("Failed to write library to bin/: " + err.Error())
        }
    }
}

// Encrypt 使用XChaCha20-Poly1305算法加密数据
// 返回加密后的数据，格式为: ciphertext + tag + nonce
func Encrypt(key, nonce, plaintext []byte) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, fmt.Errorf("XChaCha20-Poly1305 encrypt: invalid key length %d (expected %d)", len(key), KeyLength)
	}
	if len(nonce) != NonceLength {
		return nil, fmt.Errorf("XChaCha20-Poly1305 encrypt: invalid nonce length %d (expected %d)", len(nonce), NonceLength)
	}
	if len(plaintext) == 0 {
		return nil, errors.New("XChaCha20-Poly1305 encrypt: plaintext cannot be empty")
	}

	ciphertext := make([]byte, len(plaintext))
	tag := make([]byte, TagLength)

	ret := C.xchacha20_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])),
		C.size_t(len(plaintext)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
	)

	if ret < 0 {
		return nil, fmt.Errorf("XChaCha20-Poly1305 encrypt error: code %v", ret)
	}
	if int(ret) != len(plaintext) {
		return nil, fmt.Errorf("XChaCha20-Poly1305 returned length invalid: expected %d, got %v", len(plaintext), ret)
	}

	return append(append(ciphertext[:ret], tag...), nonce...), nil
}

// Decrypt 解密XChaCha20-Poly1305加密的数据
// 输入数据格式应为: ciphertext + tag + nonce
func Decrypt(key, ciphertextAndTagAndNonce []byte) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, fmt.Errorf("XChaCha20-Poly1305 decrypt: invalid key length %d (expected %d)", len(key), KeyLength)
	}
	if len(ciphertextAndTagAndNonce) < TagLength+NonceLength {
		return nil, errors.New("XChaCha20-Poly1305 decrypt: invalid input length")
	}

	// 拆分 nonce、ciphertext 和 tag
	nonce := ciphertextAndTagAndNonce[len(ciphertextAndTagAndNonce)-NonceLength:]
	ciphertextAndTag := ciphertextAndTagAndNonce[:len(ciphertextAndTagAndNonce)-NonceLength]

	if len(ciphertextAndTag) < TagLength {
		return nil, errors.New("XChaCha20-Poly1305 decrypt: ciphertext and tag too short")
	}

	ciphertext := ciphertextAndTag[:len(ciphertextAndTag)-TagLength]
	tag := ciphertextAndTag[len(ciphertextAndTag)-TagLength:]

	out := make([]byte, len(ciphertext))
	ret := C.xchacha20_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)

	if ret < 0 {
		return nil, fmt.Errorf("XChaCha20-Poly1305 decrypt error or authentication failed: code %v", ret)
	}

	if int(ret) != len(ciphertext) {
		return nil, fmt.Errorf("XChaCha20-Poly1305 decrypt returned unexpected length: expected %d, got %v", len(ciphertext), ret)
	}

	return out[:ret], nil
}
