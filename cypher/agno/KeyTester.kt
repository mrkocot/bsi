package agno

import kotlin.math.sqrt
import org.apache.commons.math3.special.Erf
import org.apache.commons.numbers.gamma.IncompleteGamma
import kotlin.math.pow

/**
 * Based on [NIST statistical test suite](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf)
 */
@Suppress("MemberVisibilityCanBePrivate")
object KeyTester {
  fun monobitTest(key: BitByteList): Pair<Boolean, String> {
    val sN = key.toList().fold(0) { acc, bitByte ->
      acc + (2 * bitByte.bitSum() - 8)
    }
    val sObs = sN / sqrt(key.bitN.toDouble())
    val pVal = Erf.erfc(sObs / sqrt(2.0))
    return (pVal >= 0.01) to "p-value = $pVal"
  }

  fun serialTest(key: BitByteList): Pair<Boolean, String> {
    val n = key.bitN
    val m = 3
    val e = key.toBinString().let {
      "$it${it.take(m-1)}"
    }
    val fiSq0 = e.calculateFiSq(n, m)
    val fiSq1 = e.calculateFiSq(n, m - 1)
    val fiSq2 = e.calculateFiSq(n, m - 2)

    val delta = fiSq0 - fiSq1
    val deltaSq = fiSq0 - 2 * fiSq1 + fiSq2

    val pVal1 = IncompleteGamma.Upper.value((2.0).pow(m - 2), delta)
    val pVal2 = IncompleteGamma.Upper.value((2.0).pow(m - 3), deltaSq)

    return (pVal1 >= 0.01 && pVal2 >= 0.01) to "p-values = ($pVal1, $pVal2)"
  }

  private fun String.calculateFiSq(n: Int, blockSize: Int): Double {
    val a = (2.0).pow(blockSize.toDouble()) / n
    val b = this.sqOccurSum(blockSize).sum()
    return a * b - n
  }

  private fun String.sqOccurSum(blockSize: Int): List<Int> =
    getAllBinaryPossibilities(blockSize)
      .map { this.windowed(size = blockSize, step = 1).count { win -> win == it } }
      .map { it * it }

  private fun getAllBinaryPossibilities(len: Int): List<String> =
    if (len <= 0) {
      listOf("")
    } else {
      getAllBinaryPossibilities(len - 1).flatMap { listOf("0$it", "1$it") }
    }
}
