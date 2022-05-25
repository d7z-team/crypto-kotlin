package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport

class SHA3Hash(val type: SHA3Type) : IHash {
    enum class SHA3Type {
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
    }

    override fun digest(source: IStreamTransport): ByteArray {
        TODO("Not yet implemented")
    }
}
