package org.d7z.crypto.hash

import org.d7z.crypto.type.SHA3Type
import org.d7z.crypto.utils.IStreamTransport

class SHA3Hash(val type: SHA3Type) : IHash {

    override fun digest(source: IStreamTransport): ByteArray {
        TODO("Not yet implemented")
    }
}
