package org.d7z.crypto.hash.sha2

import org.d7z.crypto.hash.IHash
import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach

class SHA2V1Hash(private val type: SHA2V1Type) : IHash {
    private val constK = longArrayOf(
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ).map { it.toInt() }.toIntArray()

    enum class SHA2V1Type(val size: Int, val hashes: IntArray) {
        SHA_224(
            28,
            longArrayOf(
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
            ).map { it.toInt() }.toIntArray()
        ),
        SHA_256(
            32,
            longArrayOf(
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            ).map { it.toInt() }.toIntArray()
        ),
    }

    override fun digest(source: IStreamTransport): ByteArray {
        // 摘要数据存储数组
        val digestInt = type.hashes.copyOf()
        // 计算过程中的临时数据存储数组
        val workBlock = IntArray(64)
        val endBuffer = ByteArray(64)
        var sourceSize: Long = 0

        source.bufferEach(64) { buf, size ->
            sourceSize += size
            if (size == 64) {
                fillBlock(buf, workBlock)
                iterate(workBlock, digestInt)
            } else {
                // 不可完整切片的数据,为末尾数据
                buf.copyInto(endBuffer, 0, 0, size)
            }
        }
        val endSize = (sourceSize % 64).toInt()
        // 补1操作
        endBuffer[endSize] = 0x80.toByte()
        if (endSize >= 56) {
            fillBlock(endBuffer, workBlock)
            iterate(workBlock, digestInt)
            endBuffer.fill(0)
        }
        val len = sourceSize * 8
        for (i in 0..7) {
            endBuffer[endBuffer.size - 1 - i] = (len ushr 8 * i and 0xFFL).toByte()
        }
        fillBlock(endBuffer, workBlock)
        iterate(workBlock, digestInt)

        val digest = ByteArray(digestInt.size * 4)
        for (i in digestInt.indices) {
            intToBytes(digestInt[i]).copyInto(digest, 4 * i, 0, 4)
        }
        return digest.copyOf(type.size)
    }

    private fun intToBytes(i: Int): ByteArray {
        val b = ByteArray(4)
        for (c in 0..3) {
            b[c] = ((i ushr (56 - 8 * c)) and 0xff).toByte()
        }
        return b
    }

    private fun fillBlock(container: ByteArray, workBlock: IntArray) {
        for (j in 0..15) {
            workBlock[j] = 0
            for (m in 0..3) {
                workBlock[j] = workBlock[j] or ((container[j * 4 + m].toInt() and 0x000000FF) shl (24 - m * 8))
            }
        }
        for (j in 16..63) {
            val s0 = workBlock[j - 15].rotateRight(7) xor
                workBlock[j - 15].rotateRight(18) xor
                (workBlock[j - 15] ushr 3)
            val s1 = workBlock[j - 2].rotateRight(17) xor
                workBlock[j - 2].rotateRight(19) xor
                (workBlock[j - 2] ushr 10)
            workBlock[j] = workBlock[j - 16] + s0 + workBlock[j - 7] + s1
        }
    }

    private fun iterate(words: IntArray, hs: IntArray) {
        val tempDigestInt = hs.copyOf(8)
        for (j in 0..63) {
            val tmpS0 = tempDigestInt[0].rotateRight(2) xor
                tempDigestInt[0].rotateRight(13) xor
                tempDigestInt[0].rotateRight(22)
            val maj = (tempDigestInt[0] and tempDigestInt[1]) xor
                (tempDigestInt[0] and tempDigestInt[2]) xor
                (tempDigestInt[1] and tempDigestInt[2])
            val temp2 = tmpS0 + maj
            val tmpS1 = tempDigestInt[4].rotateRight(6) xor
                tempDigestInt[4].rotateRight(11) xor
                tempDigestInt[4].rotateRight(25)
            val ch = (tempDigestInt[4] and tempDigestInt[5]) xor (tempDigestInt[4].inv() and tempDigestInt[6])
            val temp1 = tempDigestInt[7] + tmpS1 + ch + constK[j] + words[j]
            tempDigestInt[7] = tempDigestInt[6]
            tempDigestInt[6] = tempDigestInt[5]
            tempDigestInt[5] = tempDigestInt[4]
            tempDigestInt[4] = tempDigestInt[3] + temp1
            tempDigestInt[3] = tempDigestInt[2]
            tempDigestInt[2] = tempDigestInt[1]
            tempDigestInt[1] = tempDigestInt[0]
            tempDigestInt[0] = temp1 + temp2
        }
        for (j in 0..7) {
            hs[j] += tempDigestInt[j]
        }
    }
}
