package org.d7z.crypto.hash

import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach
import java.util.zip.CRC32

class JCRC32Hash : IHash {
    override fun digest(source: IStreamTransport): ByteArray {
        val crc = CRC32()
        source.bufferEach { buf, size ->
            crc.update(buf, 0, size)
        }
        var res = crc.value
        val result = ByteArray(8)
        for (i in 7 downTo 0) {
            result[i] = (res and 0xFFL).toByte()
            res = res shr 8
        }
        return result
    }
}
