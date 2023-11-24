package rsa

import agno.BitByteList
import agno.FileScanner

object RsaMain {
  private const val VERBOSE = true

  @JvmStatic
  fun main(args: Array<String>) {
    drill("cypher/resources/messages/message1.txt")
  }

  @Suppress("SameParameterValue")
  private fun drill(path: String) {
    val rsa = RSA(1024)
//    val rsa = RSA(16)
    val pubKey = rsa.publicKey.andPrint("pubKey")
    val privKey = rsa.privateKey.andPrint("privKey")

    val plain = FileScanner.fileToBitBytes(path)
    val plainText = plain.toText().andPrint("plainText")
    plain.toHexString().andPrint("_plainHex")
    val plainBlocks = RsaBlock.listFromBitByteList(plain)

//    val cypherBlocks = plainBlocks.map { it.applyToBigInteger(pubKey::crypt) }
    val cypher = plainBlocks
      .map { BitByteList.from(pubKey.crypt(it.toBigInteger())) }
    val cypherSquashed = cypher
      .let { BitByteList.fromMultiple(it) }
//    val cypher = cypherBlocks.toBitByteList()
    cypherSquashed.toHexString().andPrint("cypherHex")

    val decoded = cypher
      .map { BitByteList.from(privKey.crypt(it.toBigInteger()), 10) }
    val decodedSquashed = decoded
      .let { BitByteList.fromMultiple(it) }
      .depad()
//    val decodedBlocks = cypherBlocksAgain.map { it.applyToBigInteger(privKey::crypt) }
//    val decoded = decodedBlocks.toBitByteList()
    decodedSquashed.toHexString().andPrint("_againHex")
    val decodedText = decodedSquashed.toText().andPrint("againText")

    val plain0 = plainBlocks[0].block.toBigInteger()
    val cypher0 = cypher[0].toBigInteger()
    val again0 = decoded[0].toBigInteger()
    val m = pubKey.modulus
    val e = pubKey.exponent
    val d = privKey.exponent

    val match = if (plainText == decodedText) "Yes!" else "No..."
    println("Do texts match? $match")
  }

  private fun <T> T.andPrint(name: String): T {
    if (VERBOSE) println("$name=$this")
    return this
  }

  private fun List<RsaBlock>.toBitByteList(): BitByteList =
    RsaBlock.toBitByteList(this)
}
