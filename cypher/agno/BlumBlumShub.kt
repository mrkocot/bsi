package agno

import java.math.BigInteger
import java.util.Random

class BlumBlumShub(pBitLen: Int, qBitLen: Int) : Random() {
  private val n: BigInteger
  private var lastX: BigInteger

  init {
    val rgen = Random()
    val p = getMod4Eq3ProbablePrime(pBitLen, rgen)
    val q = getMod4Eq3ProbablePrime(qBitLen, rgen)
    this.n = p * q
    val sLimit = n - BigInteger.ONE
    this.lastX = generateBigIntegersUntil(sLimit.bitLength(), rgen) { it <= sLimit }
  }

  private fun getMod4Eq3ProbablePrime(bitLen: Int, rGen: Random): BigInteger =
    generateBigIntegersUntil(bitLen, rGen) {
      it % BigInteger("4") == BigInteger("3")
    }

  private fun generateBigIntegersUntil(
    bitLen: Int,
    rGen: Random,
    successPredicate: (BigInteger) -> Boolean
  ): BigInteger {
    var r = BigInteger(bitLen, rGen)
    while (!successPredicate(r)) r = BigInteger(bitLen, rGen)
    return r
  }

  override fun next(bits: Int): Int {
    var ret = 0
    repeat(Int.SIZE_BITS) {
      ret = ret shl 1
      if (nextBoolean()) ret += 1
    }
    return ret
  }

  /** @return `true` if generated number is even */
  override fun nextBoolean(): Boolean =
    ((lastX * lastX) % n).let {
      this.lastX = it
      it % BigInteger.TWO == BigInteger.ZERO
    }

  companion object {
    fun defaultConfig(): BlumBlumShub = BlumBlumShub(128,256)
  }
}
