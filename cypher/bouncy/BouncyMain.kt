package bouncy

object BouncyMain {
  private val castle = BouncyCastle()

  @JvmStatic
  fun main(args: Array<String>) {
    full3DES()
    fullBlowfish()

    fullAsym(BouncyCastle.Asymmetric.RSA, "RSA")
    fullAsym(BouncyCastle.Asymmetric.EC, "Elliptic Curves")

    println("MD5: ${castle.performMD5(plainPath)}")
    println("SHA512: ${castle.performSHA512(plainPath)}")

    fullSign()
  }

  private fun full3DES() {
    val key = "aabbccddeeffgghh"
    val iv = castle.perform3DES(encodingFilePair("3des"), key, false)
    castle.perform3DES(decodingFilePair("3des"), key, true, iv)
  }

  private fun fullBlowfish() {
    val key = "0123456789abcdef0123456789abcdef"
    val iv = castle.performBlowfish(encodingFilePair("chacha"), key, false)
    castle.performBlowfish(decodingFilePair("chacha"), key, true, iv)
  }

  private fun fullAsym(algo: BouncyCastle.Asymmetric, name: String) {
    val keyPair = castle.generateKeyPair(algo)
    val a = "香港人口稠密，擁有眾多島嶼，加上道路使用率之高"
    val b = castle.asymmetricEncrypt(a, keyPair.public, algo)
    val c = castle.asymmetricDecrypt(b, keyPair.private, algo)
    println("$name: ${a.withByteSize()} -> ${b.makePrintable()} -> ${c.withByteSize()}")
  }

  private fun fullSign() {
    val keyPair = castle.generateKeyPair(BouncyCastle.Asymmetric.EC)
    val signature = castle.performSignature(plainPath, keyPair.private)
    val isVerified = castle.verifySignature(plainPath, signature, keyPair.public)
    val correctString = if (isVerified) "correct" else "incorrect"
    println("Raccoon signature: ${signature.makePrintable()} (signature $correctString)")
  }
}

private fun encodingFilePair(subdir: String): Pair<String, String> = plainPath to cypherPath(subdir)
private fun decodingFilePair(subdir: String): Pair<String, String> = cypherPath(subdir) to decodedPath(subdir)

private const val plainPath = "cypher/resources/images/raccoon.jpg"
private fun cypherPath(subdir: String) = "[TEMP]$subdir-cypher.out"
private fun decodedPath(subdir: String) = "[TEMP]$subdir-decoded.jpg"

private fun ByteArray.makePrintable(): String {
  val oneLiner = this.toString(Charsets.UTF_8).filter { !it.isWhitespace() }
  val cropped = if (oneLiner.length <= 40) oneLiner else "${oneLiner.take(37)}..."
  return "$cropped[${this.size}B]"
}

private fun String.withByteSize(): String =
  "$this[${this.toByteArray(Charsets.UTF_8).size}B]"
