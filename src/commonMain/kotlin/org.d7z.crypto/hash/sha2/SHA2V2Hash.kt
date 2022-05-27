package org.d7z.crypto.hash.sha2

import org.d7z.crypto.hash.IHash
import org.d7z.crypto.utils.IStreamTransport
import org.d7z.crypto.utils.bufferEach

@Suppress("OPT_IN_USAGE")
class SHA2V2Hash(private val type: SHA2V2Type) : IHash {
    private var constK = ulongArrayOf(
        0x428a2f98d728ae22u, 0x7137449123ef65cdu, 0xb5c0fbcfec4d3b2fu, 0xe9b5dba58189dbbcu, 0x3956c25bf348b538u,
        0x59f111f1b605d019u, 0x923f82a4af194f9bu, 0xab1c5ed5da6d8118u, 0xd807aa98a3030242u, 0x12835b0145706fbeu,
        0x243185be4ee4b28cu, 0x550c7dc3d5ffb4e2u, 0x72be5d74f27b896fu, 0x80deb1fe3b1696b1u, 0x9bdc06a725c71235u,
        0xc19bf174cf692694u, 0xe49b69c19ef14ad2u, 0xefbe4786384f25e3u, 0x0fc19dc68b8cd5b5u, 0x240ca1cc77ac9c65u,
        0x2de92c6f592b0275u, 0x4a7484aa6ea6e483u, 0x5cb0a9dcbd41fbd4u, 0x76f988da831153b5u, 0x983e5152ee66dfabu,
        0xa831c66d2db43210u, 0xb00327c898fb213fu, 0xbf597fc7beef0ee4u, 0xc6e00bf33da88fc2u, 0xd5a79147930aa725u,
        0x06ca6351e003826fu, 0x142929670a0e6e70u, 0x27b70a8546d22ffcu, 0x2e1b21385c26c926u, 0x4d2c6dfc5ac42aedu,
        0x53380d139d95b3dfu, 0x650a73548baf63deu, 0x766a0abb3c77b2a8u, 0x81c2c92e47edaee6u, 0x92722c851482353bu,
        0xa2bfe8a14cf10364u, 0xa81a664bbc423001u, 0xc24b8b70d0f89791u, 0xc76c51a30654be30u, 0xd192e819d6ef5218u,
        0xd69906245565a910u, 0xf40e35855771202au, 0x106aa07032bbd1b8u, 0x19a4c116b8d2d0c8u, 0x1e376c085141ab53u,
        0x2748774cdf8eeb99u, 0x34b0bcb5e19b48a8u, 0x391c0cb3c5c95a63u, 0x4ed8aa4ae3418acbu, 0x5b9cca4f7763e373u,
        0x682e6ff3d6b2b8a3u, 0x748f82ee5defb2fcu, 0x78a5636f43172f60u, 0x84c87814a1f0ab72u, 0x8cc702081a6439ecu,
        0x90befffa23631e28u, 0xa4506cebde82bde9u, 0xbef9a3f7b2c67915u, 0xc67178f2e372532bu, 0xca273eceea26619cu,
        0xd186b8c721c0c207u, 0xeada7dd6cde0eb1eu, 0xf57d4f7fee6ed178u, 0x06f067aa72176fbau, 0x0a637dc5a2c898a6u,
        0x113f9804bef90daeu, 0x1b710b35131c471bu, 0x28db77f523047d84u, 0x32caab7b40c72493u, 0x3c9ebe0a15c9bebcu,
        0x431d67c49c100d4cu, 0x4cc5d4becb3e42b6u, 0x597f299cfc657e2au, 0x5fcb6fab3ad6faecu, 0x6c44198c4a475817u
    ).map { it.toLong() }.toLongArray()

    enum class SHA2V2Type(val size: Int, val hashes: LongArray) {
        SHA_384(
            48,
            ulongArrayOf(
                0xcbbb9d5dc1059ed8u, 0x629a292a367cd507u,
                0x9159015a3070dd17u, 0x152fecd8f70e5939u,
                0x67332667ffc00b31u, 0x8eb44a8768581511u,
                0xdb0c2e0d64f98fa7u, 0x47b5481dbefa4fa4u
            ).map { it.toLong() }.toLongArray()
        ),
        SHA_512(
            64,
            ulongArrayOf(
                0x6a09e667f3bcc908u, 0xbb67ae8584caa73bu,
                0x3c6ef372fe94f82bu, 0xa54ff53a5f1d36f1u,
                0x510e527fade682d1u, 0x9b05688c2b3e6c1fu,
                0x1f83d9abfb41bd6bu, 0x5be0cd19137e2179u
            ).map { it.toLong() }.toLongArray()
        ),
        SHA_512_224(
            28,
            ulongArrayOf(
                0x8c3d37c819544da2u, 0x73e1996689dcd4d6u,
                0x1dfab7ae32ff9c82u, 0x679dd514582f9fcfu,
                0x0f6d2b697bd44da8u, 0x77e36f7304c48942u,
                0x3f9d85a86a1d36c8u, 0x1112e6ad91d692a1u
            ).map { it.toLong() }.toLongArray()
        ),
        SHA_512_256(
            32,
            ulongArrayOf(
                0x22312194fc2bf72cu, 0x9f555fa3c84c64c2u,
                0x2393b86b6f53b151u, 0x963877195940eabdu,
                0x96283ee2a88effe3u, 0xbe5e1e2553863992u,
                0x2b0199fc2c85b8aau, 0x0eb72ddc81c52ca2u
            ).map { it.toLong() }.toLongArray()
        )
    }

    override fun digest(source: IStreamTransport): ByteArray {
        val workBlock = LongArray(80)
        var sourceSize: Long = 0
        val endBuffer = ByteArray(128)
        val digestLong = type.hashes.copyOf()
        source.bufferEach(128) { buf, size ->
            sourceSize += size
            if (size == 128) {
                fillBlock(buf, workBlock)
                iterate(workBlock, digestLong)
            } else {
                // 不可完整切片的数据,为末尾数据
                buf.copyInto(endBuffer, 0, 0, size)
            }
        }
        val endSize = (sourceSize % endBuffer.size).toInt()
        // 补1操作
        endBuffer[endSize] = 0x80.toByte()
        // 判断末尾是否有足够空间填充数据集大小
        endBuffer.fill(0, endSize + 1)
        if (endSize >= 112) {
            fillBlock(endBuffer, workBlock)
            iterate(workBlock, digestLong)
            endBuffer.fill(0, 0)
        }
        val len = sourceSize * 8L
        for (i in 0 until 8) {
            endBuffer[endBuffer.size - 1 - i] = (len ushr 8 * i and 0xFFL).toByte()
        }
        fillBlock(endBuffer, workBlock)
        iterate(workBlock, digestLong)
        val digest = ByteArray(digestLong.size * 8)
        for (i in digestLong.indices) {
            longToBytes(digestLong[i]).copyInto(digest, 8 * i, 0, 8)
        }
        return digest.copyOf(type.size)
    }

    private fun longToBytes(i: Long): ByteArray {
        val b = ByteArray(16)
        for (c in b.indices) {
            b[c] = ((i ushr (56 - 8 * c)) and 0xff).toByte()
        }
        return b
    }

    private fun iterate(workBlock: LongArray, hs: LongArray) {
        var a = hs[0]
        var b = hs[1]
        var c = hs[2]
        var d = hs[3]
        var e = hs[4]
        var f = hs[5]
        var g = hs[6]
        var h = hs[7]
        for (j in 0..79) {
            val t1 = h + (rotate(e, 14) xor rotate(e, 18) xor rotate(e, 41)) +
                ((e and f) xor (e.inv() and g)) + constK[j] + workBlock[j]
            val t2 = (rotate(a, 28) xor rotate(a, 34) xor rotate(a, 39)) +
                ((a and b) xor (a and c) xor (b and c))
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
        }

        // After finishing the compression, save the state to the buffer
        hs[0] = a + hs[0]
        hs[1] = b + hs[1]
        hs[2] = c + hs[2]
        hs[3] = d + hs[3]
        hs[4] = e + hs[4]
        hs[5] = f + hs[5]
        hs[6] = g + hs[6]
        hs[7] = h + hs[7]
    }

    private fun fillBlock(buf: ByteArray, workBlock: LongArray) {
        workBlock.fill(0)
        for (j in buf.indices step 8) {
            // Set the block value to the correct one
            var v: Long = 0
            for (d in 0..7) {
                v = (v shl 8) + (buf[d + j].toInt() and 0xff)
            }
            workBlock[j / 8] = v
        }
        for (j in 16..79) {
            // Do some math from the SHA512 algorithm
            workBlock[j] =
                func1(workBlock[j - 2]) + workBlock[j - 7] + func0(workBlock[j - 15]) + workBlock[j - 16]
        }
    }

    // Used in the message schedule
    private fun func0(x: Long): Long {
        // S1(x) ^ S8(x) ^ R7(x)
        return rotate(x, 1) xor rotate(x, 8) xor (x ushr 7)
    }

    // Used in the message schedule
    private fun func1(x: Long): Long {
        // S19(x) ^ S61(x) ^ R6(x)
        return rotate(x, 19) xor rotate(x, 61) xor (x ushr 6)
    }

    private fun rotate(x: Long, l: Int): Long {
        return (x ushr l) or (x shl (Long.SIZE_BITS - l))
    }
}
