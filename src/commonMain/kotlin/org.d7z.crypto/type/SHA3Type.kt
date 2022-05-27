package org.d7z.crypto.type

enum class SHA3Type(
    val rate: Int,
    val delimit: Int,
    val outputLen: Int
) {
    KECCAK_224(1152, 0x01, 224),
    KECCAK_256(1088, 0x01, 256),
    KECCAK_384(832, 0x01, 384),
    KECCAK_512(576, 0x01, 512),
    SHA3_224(1152, 0x06, 224),
    SHA3_256(1088, 0x06, 256),
    SHA3_384(832, 0x06, 384),
    SHA3_512(576, 0x06, 512),
    SHAKE_128(1344, 0x1F, 256),
    SHAKE_256(1088, 0x1F, 512);
}
