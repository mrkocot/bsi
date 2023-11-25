package sha

import agno.BitByteList
import agno.FileScanner

object ShaMain {
  private const val VERBOSE = true

  @JvmStatic
  fun main(args: Array<String>) {
    drill("cypher/resources/messages/message2.txt")
  }

  @Suppress("SameParameterValue")
  private fun drill(path: String) {
    val plain1 = FileScanner.fileToBitBytes(path)
    val plainText1 = plain1.toText().andPrint("plainText1")
    val plainText2 = plainText1.replaceFirst(',', '.').andPrint("plainText2")
    val plain2 = BitByteList.from(plainText2)
    val digest1 = SHA256.digest(plain1).andPrint("digest1") { it.toHexString() }
    val digest2 = SHA256.digest(plain2).andPrint("digest2") { it.toHexString() }

    (digest1 xor digest2).bitSum().let {
      it * 100.0 / digest1.bitN
    }.andPrint("bitDiff%")
  }

  private fun <T> T.andPrint(name: String, toString: (T) -> String = { it.toString() }): T {
    if (VERBOSE) println("$name=${toString(this)}")
    return this
  }
}