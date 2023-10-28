package aes

import BitByte.Companion.toByteString
import BitByte.Companion.xor

object Main {
  @JvmStatic
  fun main(args: Array<String>) {
    drill("cypher/resources/message2.txt")
  }

  private fun drill(path: String, verbose: Boolean = true) {
    val plainText = FileScanner.fileToText(path)
    val plain = FileScanner.fileToBitBytes(path)
    val byteLen = plain.size

    val key = KeyRing.generateKey(byteLen)
//    val key = KeyRing.generateKeyUnsafe(byteLen)
    val keyText = key.toByteString()

    val cypher = plain xor key
    val cypherText = cypher.toByteString()

    val plainAgain = cypher xor key
    val plainAgainText = plainAgain.toByteString()

    if (verbose) {
      println("---")
      println("plainText = $plainText")
      println("keyText = $keyText")
      println("cypherText = $cypherText")
      println("plainAgainText = $plainAgainText")
      println()
      println("Plaintext diff? ${plainText diff plainAgainText}")
      println("Is key random (monobit test)? ${KeyTester.monobitTest(key).toWord()}")
      println("---")
    }

  }

  private fun Boolean.toWord() = if (this) "Yes" else "No"

  private infix fun String.diff(other: String): Int {
    val minLen = kotlin.math.min(this.length, other.length)
    var d = 0
    repeat(minLen) {
      if (this[it] != other[it]) d++
    }
    return d
  }
}
