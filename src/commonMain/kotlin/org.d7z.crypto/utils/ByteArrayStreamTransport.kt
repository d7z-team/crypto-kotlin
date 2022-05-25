package org.d7z.crypto.utils

import kotlin.math.min

class ByteArrayStreamTransport(private val data: ByteArray) : IStreamTransport {
    private var index = 0
    private val size: Int
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
