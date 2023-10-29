package vernam

import agno.FileScanner
import agno.KeyGen
import agno.KeyTester

object Main {
  private const val VERBOSE = true

  @JvmStatic
  fun main(args: Array<String>) {
    drill("cypher/resources/messages/message1.txt")
  }

  @Suppress("SameParameterValue")
  private fun drill(path: String) {
    val plain = FileScanner.fileToBitBytes(path)
    val plainText = plain.toText().andPrint("plainText")
    val plainHex = plain.toHexString().andPrint("plainHex")
    val byteLen = plain.byteN

    val key = KeyGen.generateKey(byteLen)
    val keyText = key.toText()
    val keyHex = key.toHexString().andPrint(">>keyHex")

    val cypher = plain xor key
    val cypherText = cypher.toText()
    val cypherHex = cypher.toHexString().andPrint(">cyphHex")

    val plainAgain = cypher xor key
    val plainAgainHex = plainAgain.toHexString().andPrint("paganHex")
    val plainAgainText = plainAgain.toText().andPrint("plainAgain")

    if (VERBOSE) {
      println("Plaintext diff? ${plainText diff plainAgainText}")
      println("Is key random (monobit test)? ${KeyTester.monobitTest(key).toWord()}")
    }
  }

  private fun Boolean.toWord() = if (this) "Yes" else "No"

  private fun String.andPrint(name: String): String {
    if (VERBOSE) println("$name=$this")
    return this
  }

  private infix fun String.diff(other: String): Int {
    val minLen = kotlin.math.min(this.length, other.length)
    var d = 0
    repeat(minLen) {
      if (this[it] != other[it]) d++
    }
    return d
  }
}
