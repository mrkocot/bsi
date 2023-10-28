import java.security.SecureRandom
import java.util.Random

object KeyRing {
  fun generateKey(byteLen: Int): List<BitByte> {
    val random = SecureRandom()
    val bytes = ByteArray(byteLen).apply {
      random.nextBytes(this)
    }
    return BitByte.from(bytes)
  }

  fun generateKeyUnsafe(byteLen: Int): List<BitByte> {
    val random = Random()
    val bytes = ByteArray(byteLen).apply {
      random.nextBytes(this)
    }
    return BitByte.from(bytes)
  }
}
