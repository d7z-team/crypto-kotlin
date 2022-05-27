package org.d7z.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.BigInteger.Companion.parseString
import org.d7z.crypto.hash.SHA3Hash
import org.d7z.crypto.type.SHA3Type
import org.d7z.crypto.utils.streamTransport
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

class Sha3 {

    /**
     * Bitwise rotate left.
     *
     * @param value  unsigned long value
     * @param rotate rotate left
     * @return result
     */
    private fun leftRotate64(value: BigInteger, rotate: Int): BigInteger {
        val lp = value.shr(64 - rotate % 64)
        val rp = value.shl(rotate % 64)
        return lp.add(rp).mod(parseString("18446744073709551616", 10))
    }

    private val BIT_64 = parseString("18446744073709551615", 10)

    /**
     * Do hash.
     *
     * @param message   input data
     * @param type keccak param
     * @return byte-array result
     */
    private fun getHash(message: ByteArray, type: Parameters): ByteArray {
        val uState = IntArray(200)
        val rateInBytes = type.rate / 8
        var blockSize = 0
        var inputOffset = 0

        // Absorbing phase
        while (inputOffset < message.size) {
            blockSize = (message.size - inputOffset).coerceAtMost(rateInBytes)
            for (i in 0 until blockSize) {
                uState[i] = uState[i] xor (message[i + inputOffset].toInt() and 0xFF)
            }
            inputOffset += blockSize
            if (blockSize == rateInBytes) {
                doKeccakf(uState)
                blockSize = 0
            }
        }

        // Padding phase
        uState[blockSize] = uState[blockSize] xor type.delimit
        if (type.delimit and 0x80 != 0 && blockSize == rateInBytes - 1) {
            doKeccakf(uState)
        }
        uState[rateInBytes - 1] = uState[rateInBytes - 1] xor 0x80
        doKeccakf(uState)

        // Squeezing phase
        val byteResults = ByteArrayOutputStream()
        var tOutputLen = type.outputLen / 8
        while (tOutputLen > 0) {
            blockSize = tOutputLen.coerceAtMost(rateInBytes)
            for (i in 0 until blockSize) {
                byteResults.write(uState[i].toByte().toInt())
            }
            tOutputLen -= blockSize
            if (tOutputLen > 0) {
                doKeccakf(uState)
            }
        }
        return byteResults.toByteArray()
    }

    private fun doKeccakf(uState: IntArray) {
        val lState =
            Array(5) { arrayOf(BigInteger(0), BigInteger(0), BigInteger(0), BigInteger(0), BigInteger(0)) }
        for (i in 0..4) {
            for (j in 0..4) {
                val data = IntArray(8)
                val offset = 8 * (i + 5 * j)
                uState.copyInto(data, 0, offset, offset + data.size)
                var uLong = BigInteger(0)
                for (i in 0..7) {
                    uLong = uLong.add(BigInteger(data[i]).shl(8 * i))
                }
                lState[i][j] = uLong
            }
        }
        roundB(lState)
        uState.fill(0)
        for (i in 0..4) {
            for (j in 0..4) {
                val uLong = lState[i][j]
                val data = IntArray(8)
                val mod256 = BigInteger(256)
                for (i in 0..7) {
                    data[i] = uLong.shr(8 * i).mod(mod256).intValue(false)
                }
                val offset = 8 * (i + 5 * j)
                data.copyInto(uState, offset, 0, data.size)
            }
        }
    }

    /**
     * Permutation on the given state.
     *
     * @param state state
     */
    private fun roundB(state: Array<Array<BigInteger>>) {
        var LFSRstate = 1
        for (round in 0..23) {
            val C = arrayOfNulls<BigInteger>(5)
            val D = arrayOfNulls<BigInteger>(5)

            // θ step
            for (i in 0..4) {
                C[i] = state[i][0]
                    .xor(state[i][1]).xor(state[i][2]).xor(state[i][3]).xor(state[i][4])
            }
            for (i in 0..4) {
                D[i] = C[(i + 4) % 5]!!.xor(leftRotate64(C[(i + 1) % 5]!!, 1))
            }
            for (i in 0..4) {
                for (j in 0..4) {
                    state[i][j] = state[i][j].xor(D[i]!!)
                }
            }

            // ρ and π steps
            var x = 1
            var y = 0
            var current = state[x][y]
            for (i in 0..23) {
                val tX = x
                x = y
                y = (2 * tX + 3 * y) % 5
                val shiftValue = current
                current = state[x][y]
                state[x][y] = leftRotate64(shiftValue, (i + 1) * (i + 2) / 2)
            }

            // χ step
            for (j in 0..4) {
                val t = arrayOfNulls<BigInteger>(5)
                for (i in 0..4) {
                    t[i] = state[i][j]
                }
                for (i in 0..4) {
                    // ~t[(i + 1) % 5]
                    val invertVal = t[(i + 1) % 5]!!.xor(BIT_64)
                    // t[i] ^ ((~t[(i + 1) % 5]) & t[(i + 2) % 5])
                    state[i][j] = t[i]!!.xor(invertVal.and(t[(i + 2) % 5]!!))
                }
            }

            // ι step
            for (i in 0..6) {
                LFSRstate = ((LFSRstate shl 1) xor ((LFSRstate shr 7) * 0x71)) % 256
                // pow(2, i) - 1
                val bitPosition = (1 shl i) - 1
                if (LFSRstate and 2 != 0) {
                    state[0][0] = state[0][0].xor(BigInteger(1).shl(bitPosition))
                }
            }
        }
    }

    enum class Parameters(
        val rate: Int,
        /**
         * Delimited suffix.
         */
        val delimit: Int,
        /**
         * Output length (bits).
         */
        val outputLen: Int
    ) {
        KECCAK_224(1152, 0x01, 224),
        KECCAK_256(1088, 0x01, 256),
        KECCAK_384(832, 0x01, 384),
        KECCAK_512(576, 0x01, 512),
        SHA3_224(1152, 0x06, 224),
        SHA3_256(1088, 0x06, 256),
        SHA3_384(832, 0x06, 384),
        SHA3_512(576, 0x06, 512),
        SHAKE_128(1344, 0x1F, 256),
        SHAKE_256(1088, 0x1F, 512);
    }

    @Test
    @Throws(NoSuchAlgorithmException::class)
    fun main() {
        val data = ("The quick brown fox jumps over the lazy dog")
            .toByteArray()
        val keccak = Sha3()
        println(
            java.math.BigInteger(
                1,
                SHA3Hash(SHA3Type.SHA3_224)
                    .digest(data.streamTransport())
            ).toString(16)
        )
        println(java.math.BigInteger(1, keccak.getHash(data, Parameters.SHA3_224)).toString(16))
        println(
            java.math.BigInteger(
                1,
                MessageDigest.getInstance("sha3-224").digest(data)
            ).toString(16)
        )
    }
}
