package agno

import java.util.Random

object KeyGen {
  private val RGen = BlumBlumShub(128, 256)

  fun generateKey(byteLen: Int): BitByteList {
    val bytes = ByteArray(byteLen).apply {
      RGen.nextBytes(this)
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
