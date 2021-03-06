package org.d7z.crypto

import org.d7z.crypto.hash.JMD5Hash
import org.d7z.crypto.hash.JSHA1Hash
import org.d7z.crypto.hash.JSHA2Hash
import org.d7z.crypto.hash.JSHA3Hash
import org.d7z.crypto.hash.MD5Hash
import org.d7z.crypto.hash.SHA1Hash
import org.d7z.crypto.hash.SHA2Hash
import org.d7z.crypto.hash.SHA3Hash
import org.d7z.crypto.type.SHA2Type
import org.d7z.crypto.type.SHA3Type
import org.d7z.crypto.utils.streamTransport
import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertEquals

class TestOne {
    @Test
    fun test() {

        val data = "The quick brown fox jumps over the lazy dog.".toByteArray(Charsets.US_ASCII)
        println("MD5")
        println(BigInteger(1, JMD5Hash().digest(data.streamTransport())).toString(16))
        println(BigInteger(1, MD5Hash().digest(data.streamTransport())).toString(16))
        println("sha-1")
        println(BigInteger(1, JSHA1Hash().digest(data.streamTransport())).toString(16))
        println(BigInteger(1, SHA1Hash().digest(data.streamTransport())).toString(16))
        println("sha-2")
        for (value in SHA2Type.values()) {
            println(value)
            println(BigInteger(1, JSHA2Hash(value).digest(data.streamTransport())).toString(16))
            println(BigInteger(1, SHA2Hash(value).digest(data.streamTransport())).toString(16))
        }
        println("sha-3")
        for (value in SHA3Type.values()) {
            println(value)
            try {
                println(BigInteger(1, JSHA3Hash(value).digest(data.streamTransport())).toString(16))
            } catch (e: Exception) {
                println("$value 错误！ ${e.message}")
            }
            println(BigInteger(1, SHA3Hash(value).digest(data.streamTransport())).toString(16))
        }
    }

    @Test
    fun autoTest() {
        val src = StringBuilder()
        for (i in 0..1000) {
            src.append("a")
            val data = src.toString().toByteArray(Charsets.ISO_8859_1)
            val md5Data1 = BigInteger(1, JMD5Hash().digest(data.streamTransport())).toString(16)
            val md5Data2 = BigInteger(1, MD5Hash().digest(data.streamTransport())).toString(16)
            assertEquals(md5Data1, md5Data2, "current: ${src.length}")
            val shaData1 = BigInteger(1, JSHA1Hash().digest(data.streamTransport())).toString(16)
            val shaData2 = BigInteger(1, SHA1Hash().digest(data.streamTransport())).toString(16)
            assertEquals(shaData1, shaData2, "current: ${src.length}")
            val sha224Data1 = BigInteger(1, JSHA2Hash(SHA2Type.SHA_224).digest(data.streamTransport())).toString(16)
            val sha224Data2 = BigInteger(1, SHA2Hash(SHA2Type.SHA_224).digest(data.streamTransport())).toString(16)
            assertEquals(sha224Data1, sha224Data2, "current: ${src.length}")
            val sha256Data1 = BigInteger(1, JSHA2Hash(SHA2Type.SHA_256).digest(data.streamTransport())).toString(16)
            val sha256Data2 = BigInteger(1, SHA2Hash(SHA2Type.SHA_256).digest(data.streamTransport())).toString(16)
            assertEquals(sha256Data1, sha256Data2, "current: ${src.length}")
            val sha384Data1 = BigInteger(1, JSHA2Hash(SHA2Type.SHA_384).digest(data.streamTransport())).toString(16)
            val sha384Data2 = BigInteger(1, SHA2Hash(SHA2Type.SHA_384).digest(data.streamTransport())).toString(16)
            assertEquals(sha384Data1, sha384Data2, "current: ${src.length}")
            val sha512Data1 = BigInteger(1, JSHA2Hash(SHA2Type.SHA_512).digest(data.streamTransport())).toString(16)
            val sha512Data2 = BigInteger(1, SHA2Hash(SHA2Type.SHA_512).digest(data.streamTransport())).toString(16)
            assertEquals(sha512Data1, sha512Data2, "current: ${src.length}")
            val sha512To224Data1 =
                BigInteger(1, JSHA2Hash(SHA2Type.SHA_512_224).digest(data.streamTransport())).toString(16)
            val sha512To224Data2 =
                BigInteger(1, SHA2Hash(SHA2Type.SHA_512_224).digest(data.streamTransport())).toString(16)
            assertEquals(sha512To224Data1, sha512To224Data2, "current: ${src.length}")
            val sha512To256Data1 =
                BigInteger(1, JSHA2Hash(SHA2Type.SHA_512_256).digest(data.streamTransport())).toString(16)
            val sha512To256Data2 =
                BigInteger(1, SHA2Hash(SHA2Type.SHA_512_256).digest(data.streamTransport())).toString(16)
            assertEquals(sha512To256Data1, sha512To256Data2, "current: ${src.length}")
        }
    }
}
