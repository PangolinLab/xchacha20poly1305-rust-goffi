// xchacha20_poly1305_interface.h
#ifndef XCHACHA20_POLY1305_INTERFACE_H
#define XCHACHA20_POLY1305_INTERFACE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 使用XChaCha20-Poly1305算法加密数据
 *
 * @param key 加密密钥，长度必须为32字节
 * @param nonce 随机数，长度必须为24字节
 * @param in 待加密的明文数据
 * @param in_len 明文数据长度
 * @param out 输出的密文数据缓冲区
 * @param tag 输出的16字节认证标签
 * @return 成功时返回加密数据长度，失败时返回负值错误码
 */
int32_t xchacha20_encrypt(
    const uint8_t *key,     // length 32
    const uint8_t *nonce,   // length 24
    const uint8_t *in,      // plaintext
    size_t in_len,
    uint8_t *out,           // ciphertext
    uint8_t *tag            // 16 bytes auth tag
);

/**
 * @brief 使用XChaCha20-Poly1305算法解密数据
 *
 * @param key 解密密钥，长度必须为32字节
 * @param nonce 随机数，长度必须为24字节
 * @param in 待解密的密文数据（不包含标签）
 * @param in_len 密文数据长度
 * @param tag 16字节认证标签
 * @param out 输出的明文数据缓冲区
 * @return 成功时返回解密数据长度，失败时返回负值错误码
 */
int32_t xchacha20_decrypt(
    const uint8_t *key,     // length 32
    const uint8_t *nonce,   // length 24
    const uint8_t *in,      // ciphertext without tag
    size_t in_len,
    const uint8_t *tag,     // 16 bytes auth tag
    uint8_t *out            // plaintext
);

#ifdef __cplusplus
}
#endif

#endif // XCHACHA20_POLY1305_INTERFACE_H
