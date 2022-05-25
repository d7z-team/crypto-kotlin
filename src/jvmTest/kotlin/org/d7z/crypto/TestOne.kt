package org.d7z.crypto

import org.d7z.crypto.hash.JMD5Hash
import org.d7z.crypto.hash.JSHA1Hash
import org.d7z.crypto.hash.MD5Hash
import org.d7z.crypto.utils.streamTransport
import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertEquals

class TestOne {
    @Test
    fun test() {

        val data = "hello world".toByteArray(Charsets.US_ASCII)
        println("MD5")
        println(JMD5Hash().loadHashToHexText(data.streamTransport()))
        println(BigInteger(1, JMD5Hash().loadHash(data.streamTransport())).toString(16))
        println(BigInteger(1, MD5Hash().loadHash(data.streamTransport())).toString(16))
        println("sha-1")

        val loadHash = JSHA1Hash().loadHash(data.streamTransport())
        println(BigInteger(1, loadHash).toString(16))
        val digestOfBytes = SHA1().getDigestOfBytes(data)
        println(BigInteger(1, digestOfBytes).toString(16))
        println(loadHash.joinToString { String.format("%-9S", it.toString(2)) })
        println(digestOfBytes.joinToString { String.format("%-9S", it.toString(2)) })
    }

    @Test
    fun autoTest() {
        val src = StringBuilder()
        for (i in 0..1000) {
            src.append("a")
            val data = src.toString().toByteArray(Charsets.ISO_8859_1)
            val md5Data1 = BigInteger(1, JMD5Hash().loadHash(data.streamTransport())).toString(16)
            val md5Data2 = BigInteger(1, MD5Hash().loadHash(data.streamTransport())).toString(16)
            assertEquals(md5Data1, md5Data2, "current: ${src.length}")
            val shaData1 = BigInteger(1, JSHA1Hash().loadHash(data.streamTransport())).toString(16)
            val shaData2 = BigInteger(1, SHA1().getDigestOfBytes(data)).toString(16)
            assertEquals(shaData1, shaData2, "current: ${src.length}")
        }
    }
}
