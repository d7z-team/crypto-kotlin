package org.d7z.crypto.utils

import kotlin.math.min

/**
 *
 *  带缓冲区的循环读取
 *
 * @receiver IStreamTransport
 * @param bufferSize Int
 */
fun IStreamTransport.bufferEach(bufferSize: Int = 1024, func: (buf: ByteArray, size: Int) -> Unit) {
    val buffer = ByteArray(bufferSize)
    while (true) {
        var readSize = read(buffer, 0, bufferSize)
        while (readSize != -1 && readSize != bufferSize) {
            val read = read(buffer, readSize, bufferSize - readSize)
            if (read == -1) {
                break
            } else {
                readSize += read
            }
        }
        if (readSize == -1) {
            break
        }
        func(buffer, readSize)
    }
}

class ByteArrayStreamTransport(val data: ByteArray) : IStreamTransport {
    var index = 0
    val size: Int
        get() = data.size - index

    override fun available(): Boolean {
        return index < data.size
    }

    override fun read(container: ByteArray, offset: Int, size: Int): Int {
        if (offset + size > container.size) {
            throw IndexOutOfBoundsException("offset($offset) + size($size) > container.size(${container.size}) .")
        }
        val copySize = min(this.size, size)
        if (copySize <= 0) {
            return -1
        }
        data.copyInto(container, offset, index, index + copySize)
        index += copySize
        return copySize
    }

    override fun close() {
    }
}

fun ByteArray.streamTransport(): IStreamTransport = ByteArrayStreamTransport(this)
