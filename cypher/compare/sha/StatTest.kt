package compare.sha

import agno.BitByteList
import org.apache.commons.math3.distribution.NormalDistribution
import org.apache.commons.math3.stat.inference.TTest
import kotlin.math.abs
import kotlin.math.floor

object StatTest {
  fun hammingTest(
    hashPairs: List<Pair<ByteArray, ByteArray>>,
  ): Result {
    val diffs = hashPairs.map { it.byteDiff().toDouble() }
    val hashLen = (hashPairs.first().first.size * 8)

    if (VERBOSE) {
      println("HAM - Differences: $diffs")
      println("HAM - Average difference: ${diffs.average()} out of $hashLen")
    }

    val expected = hashLen / 2.0
    val alpha = .05
    return testMean(diffs, expected).toResult(alpha)
  }

  @OptIn(ExperimentalStdlibApi::class)
  fun predictionTest(
    hashPairs: List<Pair<ByteArray, ByteArray>>,
  ): Result {
    val hashes = hashPairs.flatMap { listOf(it.first, it.second) }.map { BitByteList.from(it) }
    val hashN = hashes.size
    val stats = (0 ..< hashes.first().bitN).map { bitIndex ->
      hashes.sumOf {
        if (it.getBit(bitIndex)) 1L else 0L
      } / hashN.toDouble()
    }

    if (VERBOSE) {
      println("PRED - 1s chance: $stats")
      println("PRED - Average chance: ${stats.average()}")
    }

    val expected = 0.5
    val alpha = .05
    return testMean(stats, expected).toResult(alpha)
  }

  fun serialTest(
    hashPairs: List<Pair<ByteArray, ByteArray>>,
  ): List<Result> {
    val hashes = hashPairs.flatMap { listOf(it.first, it.second) }.map { BitByteList.from(it) }
    val stss = hashes.map { SerialTestStatisticalSummary(it) }
    val alpha = .05
    val nd = NormalDistribution()
    val stats = stss.map { (it.theR - it.muR) / it.sd }
    val pVals = stats.map { 2 * (1 - nd.cumulativeProbability(abs(it))) }

    if (VERBOSE) {
      println("SER - p-vals: $pVals")
    }

    return pVals.map { it.toResult(alpha) }
  }

  private fun Pair<ByteArray, ByteArray>.byteDiff(): Int {
    if (first.size != second.size) error("Different sizes!")
    return first.zip(second).sumOf { it.bitDiff() }
  }

  private fun Pair<Byte, Byte>.bitDiff(): Int {
    var a = this.first.toInt()
    var b = this.second.toInt()
    var res = 0
    repeat(8) {
      if (abs(a % 2) != abs(b % 2)) res++
      a = a.ownFloorDiv()
      b = b.ownFloorDiv()
    }
    return res
  }

  private fun Int.ownFloorDiv(): Int =
    floor(this / 2.0).toInt()

  /** @return `false` if the hypothesis is to be rejected */
  private fun testMean(
    data: List<Double>,
    expected: Double,
  ): Double {
    val pVal = TTest().tTest(expected, data.toDoubleArray())
    return pVal
  }

  private fun Double.toResult(alpha: Double) =
    Result(this, this > alpha)

  data class Result(
    val pValue: Double,
    val accept: Boolean,
  ) {
    override fun toString(): String {
      val acceptString = if (accept) "maybe accepted" else "rejected"
      return "p-value = $pValue | Hypothesis $acceptString."
    }
  }
}

private fun <T> T.andDebugPrint(): T =
  this.also { println(it) }

private const val VERBOSE = true
