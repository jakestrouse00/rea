/*
 * REA curated crypto-constant pack for YARA-X.
 *
 * Every rule matches a short, algorithm-specific constant table that appears in
 * compiled implementations of the named primitive. Matches are indicators, not
 * proof of use: a compiler, table generator, or test vector can share the same
 * bytes. REA reports rule identity, offsets, and matched field names only; the
 * matched bytes never reach Evidence.
 *
 * Pack version 1. Keep third_party/yara-rules/crypto/manifest.json in step with
 * the SHA-256 of this file.
 */

rule crypto_aes_sbox_head
{
    meta:
        namespace = "crypto/symmetric"
        description = "First 16 bytes of the AES S-box"
        algorithm = "AES"
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        $sbox
}

rule crypto_aes_inverse_sbox_head
{
    meta:
        namespace = "crypto/symmetric"
        description = "First 16 bytes of the AES inverse S-box"
        algorithm = "AES"
    strings:
        $inv_sbox = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
    condition:
        $inv_sbox
}

rule crypto_sha256_round_constants_head
{
    meta:
        namespace = "crypto/hash"
        description = "First two SHA-256 round constants (0x428a2f98, 0xd728ae22-order table)"
        algorithm = "SHA-256"
    strings:
        $k = { 42 8A 2F 98 D7 28 AE 22 91 44 23 38 13 42 C6 EF }
    condition:
        $k
}

rule crypto_md5_initial_state
{
    meta:
        namespace = "crypto/hash"
        description = "MD5 initial state little-endian words"
        algorithm = "MD5"
    strings:
        $iv = { 01 23 45 67 89 AB CD EF }
    condition:
        $iv
}

rule crypto_crc32_reversed_polynomial
{
    meta:
        namespace = "checksum"
        description = "CRC-32 reversed polynomial 0xEDB88320"
        algorithm = "CRC-32"
    strings:
        $poly_be = { ED B8 83 20 }
        $poly_le = { 20 83 B8 ED }
    condition:
        any of them
}

rule crypto_tea_delta
{
    meta:
        namespace = "crypto/symmetric"
        description = "TEA/XTEA delta constant 0x9E3779B9"
        algorithm = "TEA"
    strings:
        $delta_le = { B9 79 37 9E }
        $delta_be = { 9E 37 79 B9 }
    condition:
        any of them
}

rule crypto_blowfish_p_array_head
{
    meta:
        namespace = "crypto/symmetric"
        description = "First Blowfish P-array constant 0x243F6A88 followed by 0x85A308D3"
        algorithm = "Blowfish"
    strings:
        $p = { 88 6A 3F 24 D3 08 A3 85 }
    condition:
        $p
}

rule crypto_salsa20_sigma
{
    meta:
        namespace = "crypto/stream"
        description = "Salsa20/ChaCha20 sigma constant"
        algorithm = "Salsa20/ChaCha20"
    strings:
        $sigma = "expand 32-byte k"
    condition:
        $sigma
}

rule crypto_pkcs1_sha256_digest_info
{
    meta:
        namespace = "crypto/signature"
        description = "PKCS#1 v1.5 DigestInfo prefix for SHA-256"
        algorithm = "RSA/PKCS#1"
    strings:
        $prefix = { 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 }
    condition:
        $prefix
}

rule crypto_base64_alphabet
{
    meta:
        namespace = "encoding"
        description = "Standard Base64 alphabet"
        algorithm = "Base64"
    strings:
        $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    condition:
        $alphabet
}
