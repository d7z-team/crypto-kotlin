package org.d7z.crypto

import org.d7z.crypto.hash.CRC32Hash
import org.d7z.crypto.hash.JCRC32Hash
import org.d7z.crypto.type.MessageDigestType
import org.d7z.crypto.utils.digestText
import org.d7z.crypto.utils.streamTransport
import org.d7z.crypto.utils.toHexText
import org.junit.jupiter.api.Test

internal class MessageDigestTest {

    @Test
    fun getInstance() {
        println(MessageDigest.getInstance(MessageDigestType.SHA_3_KECCAK_224).digestText("name"))
        val toByteArray = "CRC".toByteArray()
        println(CRC32Hash().digest(toByteArray.streamTransport()).toHexText())
        println(JCRC32Hash().digest(toByteArray.streamTransport()).toHexText())
    }

    @Test
    fun testGetInstance() {
    }
}
