package agno

import java.security.SecureRandom
import java.util.Random

object KeyGen {
  fun generateKey(byteLen: Int): BitByteList {
    val random = SecureRandom()
    val bytes = ByteArray(byteLen).apply {
      random.nextBytes(this)
    }
    return BitByteList.from(bytes)
  }

  fun generateKeyUnsafe(byteLen: Int): BitByteList {
    val random = Random()
    val bytes = ByteArray(byteLen).apply {
      random.nextBytes(this)
    }
    return BitByteList.from(bytes)
  }
}
