package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport

class SHA3Hash(val hashSize: Int) : IHash {

    override fun loadHash(source: IStreamTransport): ByteArray {
        TODO("Not yet implemented")
    }
}