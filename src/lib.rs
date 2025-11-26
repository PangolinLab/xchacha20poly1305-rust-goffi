use std::os::raw::{c_uchar, c_int};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce, KeyInit};
use chacha20poly1305::aead::{Aead};
use std::slice;

#[repr(C)]
pub enum CryptoResult {
    Success = 0,
    InvalidInput = -1,
    EncryptionFailed = -2,
    DecryptionFailed = -3,
}

#[unsafe(no_mangle)]
pub extern "C" fn xchacha20_encrypt(
    key_ptr: *const c_uchar,
    nonce_ptr: *const c_uchar,
    in_ptr: *const c_uchar,
    in_len: usize,
    out_ptr: *mut c_uchar,
    tag_ptr: *mut c_uchar,
) -> c_int {
    // 输入验证
    if key_ptr.is_null() || nonce_ptr.is_null() || in_ptr.is_null() || out_ptr.is_null() || tag_ptr.is_null() {
        return CryptoResult::InvalidInput as c_int;
    }

    // 安全地从原始指针创建切片
    let key = unsafe { slice::from_raw_parts(key_ptr, 32) };
    let nonce = unsafe { slice::from_raw_parts(nonce_ptr, 24) };
    let plaintext = unsafe { slice::from_raw_parts(in_ptr, in_len) };

    // 初始化加密器
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    
    // 执行加密
    match cipher.encrypt(XNonce::from_slice(nonce), plaintext) {
        Ok(ciphertext) => {
            // 将密文复制到输出缓冲区
            unsafe { 
                std::ptr::copy_nonoverlapping(ciphertext.as_ptr(), out_ptr, ciphertext.len() - 16);
            }
            
            // 将认证标签复制到标签缓冲区
            let tag = &ciphertext[ciphertext.len() - 16..];
            unsafe { 
                std::ptr::copy_nonoverlapping(tag.as_ptr(), tag_ptr, 16);
            }
            
            (ciphertext.len() - 16) as c_int
        }
        Err(_) => CryptoResult::EncryptionFailed as c_int,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn xchacha20_decrypt(
    key_ptr: *const c_uchar,
    nonce_ptr: *const c_uchar,
    in_ptr: *const c_uchar,
    in_len: usize,
    tag_ptr: *const c_uchar,
    out_ptr: *mut c_uchar,
) -> c_int {
    // 输入验证
    if key_ptr.is_null() || nonce_ptr.is_null() || in_ptr.is_null() || tag_ptr.is_null() || out_ptr.is_null() {
        return CryptoResult::InvalidInput as c_int;
    }

    // 安全地从原始指针创建切片
    let key = unsafe { slice::from_raw_parts(key_ptr, 32) };
    let nonce = unsafe { slice::from_raw_parts(nonce_ptr, 24) };
    let ciphertext = unsafe { slice::from_raw_parts(in_ptr, in_len) };
    let tag = unsafe { slice::from_raw_parts(tag_ptr, 16) };

    // 重新组合密文和标签
    let mut full_ciphertext = Vec::with_capacity(ciphertext.len() + 16);
    full_ciphertext.extend_from_slice(ciphertext);
    full_ciphertext.extend_from_slice(tag);

    // 初始化解密器
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    
    // 执行解密
    match cipher.decrypt(XNonce::from_slice(nonce), full_ciphertext.as_ref()) {
        Ok(plaintext) => {
            // 将明文复制到输出缓冲区
            unsafe { 
                std::ptr::copy_nonoverlapping(plaintext.as_ptr(), out_ptr, plaintext.len());
            }
            plaintext.len() as c_int
        }
        Err(_) => CryptoResult::DecryptionFailed as c_int,
    }
}
