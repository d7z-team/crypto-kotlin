package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport

class SHA2Hash(val hashSize: Int) : IHash {

    override fun digest(source: IStreamTransport): ByteArray {
        TODO("Not yet implemented")
    }
}
