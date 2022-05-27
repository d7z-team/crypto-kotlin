package org.d7z.crypto

import org.d7z.crypto.factory.IMessageDigest

actual object CryptoPlatform {
    actual val messageDigest: IMessageDigest
        get() = throw AlgorithmInitializationException("todo", "native 平台暂无任何本地实现")
}
