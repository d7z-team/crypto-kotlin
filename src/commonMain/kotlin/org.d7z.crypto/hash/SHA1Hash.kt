package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport

class SHA1Hash : IHash {

    private val abcde = intArrayOf(
        0x67452301, -0x10325477, -0x67452302, 0x10325476, -0x3c2d1e10
    )
    override fun loadHash(source: IStreamTransport): ByteArray {
        TODO("Not yet implemented")
    }
}
