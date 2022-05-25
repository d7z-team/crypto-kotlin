package org.d7z.crypto.utils

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

fun ByteArray.streamTransport(): IStreamTransport = ByteArrayStreamTransport(this)
