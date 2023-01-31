use std::ffi::c_void;
use hashes::hex::ToHex;

// Rust bindings for Apple CommonCrypto Framework
extern "C" {
    /// Stateless, one-shot encrypt or decrypt operation. This basically performs a sequence of
    /// CCCrytorCreate(), CCCryptorUpdate(), CCCryptorFinal(), and CCCryptorRelease().
    ///
    /// # Arguments
    ///
    /// * `op`: Defines the basic operation: kCCEncrypt or kCCDecrypt.
    /// * `alg`: Defines the encryption algorithm.
    /// * `options`: A word of flags defining options. See discussion for the CCOptions type.
    /// * `key`: Raw key material, length keyLength bytes.
    /// * `key_length`: Length of key material. Must be appropriate for the select algorithm.
    /// Some algorithms may provide for varying key lengths.
    /// * `iv`: Initialization vector, optional. Used for Cipher Block Chaining (CBC) mode. If
    /// present, must be the same length as the selected algorithm's block size. If CBC mode is
    /// selected (by the absence of any mode bits in the options flags) and no IV is present, a
    /// NULL (all zeroes) IV will be used. This is ignored if ECB mode is used or if a stream
    /// cipher algorithm is selected. For sound encryption, always initialize IV with random data.
    /// * `data_in`: Data to encrypt or decrypt, length dataInLength bytes.
    /// * `data_in_length`: Length of data to encrypt or decrypt.
    /// * `data_out`: Result is written here. Allocated by caller. Encryption and decryption can be
    /// performed "in-place", with the same buffer used for input and output.
    /// * `data_out_available`: The size of the dataOut buffer in bytes.
    /// * `data_out_moved`: On successful return, the number of bytes written to dataOut. If
    /// kCCBufferTooSmall is returned as a result of insufficient buffer space being provided, the
    /// required buffer space is returned here.
    ///
    /// returns: CryptorStatus
    ///
    /// kCCBufferTooSmall: indicates insufficent space in the dataOut buffer. In this case, the *dataOutMoved parameter will indicate the size of the buffer needed to complete the operation. The operation can be retried with minimal runtime penalty.
    ///
    /// kCCAlignmentError: indicates that dataInLength was not properly aligned. This can only be returned for block ciphers, and then only when decrypting or when encrypting with block with padding disabled.
    ///
    /// kCCDecodeError: Indicates improperly formatted ciphertext or a "wrong key" error; occurs only during decrypt operations.
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    /// API_AVAILABLE(macos(10.4), ios(2.0));
    fn CCCrypt(
        op: CCOperation,
        alg: u32,
        options: u32,
        key: *const c_void,
        key_length: usize,
        // optional initialization vector
        iv: *const c_void,
        // optional per op and alg
        data_in: *const c_void,
        data_in_length: usize,
        // data RETURNED here
        data_out: *mut c_void,
        data_out_available: usize,
        data_out_moved: *mut usize
    ) -> i32;
}

/// Operations that an CCCryptor can perform.
#[repr(u32)]
pub enum CCOperation {
    /// Symmetric encryption
    Encrypt = 0,
    /// Symmetric decryption
    Decrypt = 1,
}

#[repr(u32)]
pub enum CCAlgorithm {
    /// Advanced Encryption Standard, 128-bit block
    AES = 0,
    /// Data Encryption Standard
    DES,
    /// Triple-DES, three key, EDE configuration
    TripleDES,
    /// CAST
    CAST,
    /// RC4 stream cipher
    RC4,
    RC2,
    /// Blowfish block cipher
    Blowfish
}

/// Options flags, passed to CCCryptorCreate()
/// Default is CBC
#[repr(u32)]
enum CCOptions {
    /// Perform PKCS7 padding
    PKCS7Padding   = 0x0001,
    /// Electronic Code Book Mode
    ECBMode        = 0x0002
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(i32)]
enum CryptorStatus {
    Success          = 0,
    ParamError       = -4300,
    BufferTooSmall   = -4301,
    MemoryFailure    = -4302,
    AlignmentError   = -4303,
    DecodeError      = -4304,
    Unimplemented    = -4305,
    Overflow         = -4306,
    RNGFailure       = -4307,
    UnspecifiedError = -4308,
    CallSequenceError= -4309,
    KeySizeError     = -4310,
    InvalidKey       = -4311,
}

fn cc_crypt_aes256(op: CCOperation,
                   key: Vec<u8>,
                   iv: Vec<u8>,
                   input: &Vec<u8>) -> Option<Vec<u8>> {
    let mut encrypted_size = 0usize;
    let buffer_size = 16 + input.len();
    let output = &mut Vec::<u8>::with_capacity(buffer_size);
    // println!("input: {}", input.to_hex());
    println!("encryptWithDHECDSAKey: input: {} key_data: {} iv: {}", input.to_hex(), key.to_hex(), iv.to_hex());
    unsafe {
        let status = CCCrypt(
            op,
            0,
            0x0001,
            key.as_ptr() as *const c_void,
            32,
            iv.as_ptr() as *const c_void,
            input.as_ptr() as *const c_void,
            input.len(),
            output.as_mut_ptr() as *mut c_void,
            buffer_size,
            &mut encrypted_size as *mut usize,
        );//3725d3b9ec4d739a842116277c6ace81549089be0d11a54ee09a99dcf7ac695a8ea56d41bf0b62def90b6f78f8b0aca9
        // println!("out.1 {:?}...{:?}", &output[..16], &output[32..]);
        output.resize(encrypted_size, 0);
        // output.resize(encrypted_size, 0);
        println!("out.2 {}", output.to_hex());
        (status == 0).then_some(output.clone())
    }
}

pub fn encrypt_aes256(
    key: Vec<u8>,
    iv: Vec<u8>,
    input: &Vec<u8>) -> Option<Vec<u8>> {
    let mut destination = iv.clone();
    cc_crypt_aes256(CCOperation::Encrypt, key, iv, input)
        .map(|encrypted| {
            destination.extend(encrypted);
            destination
        })
}

pub fn decrypt_aes256(
    key: Vec<u8>,
    iv_size: usize,
    input: &Vec<u8>) -> Option<Vec<u8>> {
    let mut destination = input[..iv_size].to_vec();
    cc_crypt_aes256(CCOperation::Decrypt, key, destination.clone(), &input[iv_size..].to_vec())
        .map(|decrypted| {
            destination.extend(decrypted);
            destination
        })

}
