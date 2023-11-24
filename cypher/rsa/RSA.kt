package rsa

import agno.BlumBlumShub
import java.math.BigInteger
import java.util.Random

class RSA(modulusBits: Int) {
  private val n: BigInteger  // modulus
  private val e: BigInteger  // public exponent
  private val d: BigInteger  // private exponent

  val publicKey: Key
  val privateKey: Key

  init {
//    if (modulusBits < 512) error("You must be stupid to use not even RSA-512!")

    val pLen = modulusBits.floorDiv(3)
    val qLen = modulusBits - pLen
    val rGen: Random = BlumBlumShub.defaultConfig()

    val p = BigInteger.probablePrime(pLen, rGen)
    val q = BigInteger.probablePrime(qLen, rGen)
//    val p = BigInteger("61")
//    val q = BigInteger("53")


    val f = lcm(p - BigInteger.ONE, q - BigInteger.ONE)
//    val eLen = f.bitLength() - 32  // arbitrary - lower bit length ensures e < f
    val eLen = f.bitLength() - 3  // arbitrary - lower bit length ensures e < f

    n = p * q
    e = BigInteger.probablePrime(eLen, rGen)
//    e = BigInteger("17")
    d = e.modInverse(f)

    publicKey = Key(n, e)
    privateKey = Key(n, d)
  }

  private fun lcm(a: BigInteger, b: BigInteger): BigInteger =
    (a * b) / a.gcd(b)


  data class Key(
    val modulus: BigInteger,
    val exponent: BigInteger,
  ) {
    /** When used on public key will encrypt; if on private key - decrypt */
    fun crypt(message: BigInteger): BigInteger =
      message.modPow(exponent, modulus)
  }
}
