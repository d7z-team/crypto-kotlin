package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport

class SHA2Hash(val type: SHA2Type) : IHash {

    enum class SHA2Type {
        SHA_224,
        SHA_256,
        SHA_512_224,
        SHA_512_256,
        SHA_384,
        SHA_512,
    }

    override fun digest(source: IStreamTransport): ByteArray {
        TODO("Not yet implemented")
    }
}
