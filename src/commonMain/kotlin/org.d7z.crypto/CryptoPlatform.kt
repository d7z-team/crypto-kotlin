package org.d7z.crypto

import org.d7z.crypto.factory.IMessageDigest

expect object CryptoPlatform {
    val messageDigest: IMessageDigest
}
