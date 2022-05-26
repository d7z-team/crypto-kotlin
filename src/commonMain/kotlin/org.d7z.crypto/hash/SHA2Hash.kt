package org.d7z.crypto.hash

import org.d7z.crypto.type.SHA2Type
import org.d7z.crypto.utils.IStreamTransport

class SHA2Hash(val type: SHA2Type) : IHash {

    override fun digest(source: IStreamTransport): ByteArray {
        TODO("Not yet implemented")
    }
}
