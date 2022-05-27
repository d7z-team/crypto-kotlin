package org.d7z.crypto.hash

import org.d7z.crypto.hash.sha2.SHA2V1Hash
import org.d7z.crypto.hash.sha2.SHA2V2Hash
import org.d7z.crypto.type.SHA2Type
import org.d7z.crypto.utils.IStreamTransport

class SHA2Hash(type: SHA2Type) : IHash {
    private val child = when (type) {
        SHA2Type.SHA_224 -> SHA2V1Hash(SHA2V1Hash.SHA2V1Type.SHA_224)
        SHA2Type.SHA_256 -> SHA2V1Hash(SHA2V1Hash.SHA2V1Type.SHA_256)
        SHA2Type.SHA_512_224 -> SHA2V2Hash(SHA2V2Hash.SHA2V2Type.SHA_512_224)
        SHA2Type.SHA_512_256 -> SHA2V2Hash(SHA2V2Hash.SHA2V2Type.SHA_512_256)
        SHA2Type.SHA_384 -> SHA2V2Hash(SHA2V2Hash.SHA2V2Type.SHA_384)
        SHA2Type.SHA_512 -> SHA2V2Hash(SHA2V2Hash.SHA2V2Type.SHA_512)
    }

    override fun digest(source: IStreamTransport) = child.digest(source)
}
