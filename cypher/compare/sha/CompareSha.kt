package compare.sha

import java.io.File

object CompareSha {
  @JvmStatic
  fun main(args: Array<String>) {
    val hashPairs = readHashPairs()

    hashPairs.doHamming { it.sha2 }.printResult("SHA-2 Hamming")
    hashPairs.doHamming { it.sha3 }.printResult("SHA-3 Hamming")
    hashPairs.doHamming { it.ascon }.printResult("ASCON Hamming")

    hashPairs.doPrediction { it.sha2 }.printResult("SHA-2 Prediction")
    hashPairs.doPrediction { it.sha3 }.printResult("SHA-3 Prediction")
    hashPairs.doPrediction { it.ascon }.printResult("ASCON Prediction")

    hashPairs.doSerial { it.sha2 }.printResult("SHA-2 Serial")
    hashPairs.doSerial { it.sha3 }.printResult("SHA-3 Serial")
    hashPairs.doSerial { it.ascon }.printResult("ASCON Serial")
  }

  private fun readHashPairs(): HashPairs {
    val rows = readCsv().drop(1) // we ignore the header
    val hashSets: List<HashX3<String>> = rows.map { HashX3.fromRow(it) }
    val byteHashes = hashSets.map { x3 ->
      x3.map { it.hexToBytes() }
    }
    return byteHashes.pair()
  }

  private fun readCsv(): List<String> =
    File(CSV_PATH).bufferedReader(Charsets.US_ASCII).readLines()

  private fun <A> List<A>.pair(): List<Pair<A, A>> {
    if (size % 2 != 0) error("Odd number of elements")
    return chunked(2).map { (a, b) -> a to b }
  }

  private fun HashPairs.doHamming(extractor: (HashX3<ByteArray>) -> ByteArray): StatTest.Result {
    val pairs = this.map { extractor(it.first) to extractor(it.second) }
    return StatTest.hammingTest(pairs)
  }

  private fun HashPairs.doPrediction(extractor: (HashX3<ByteArray>) -> ByteArray): StatTest.Result {
    val pairs = this.map { extractor(it.first) to extractor(it.second) }
    return StatTest.predictionTest(pairs)
  }

  private fun HashPairs.doSerial(extractor: (HashX3<ByteArray>) -> ByteArray): List<StatTest.Result> {
    val pairs = this.map { extractor(it.first) to extractor(it.second) }
    return StatTest.serialTest(pairs)
  }
}

private typealias HashPairs = List<Pair<HashX3<ByteArray>, HashX3<ByteArray>>>

private const val CSV_PATH =
  "/Users/mkocot/Documents/ucz/BSI/LabMonorepo/cypher/resources/hash/hash.csv"

private fun String.hexToBytes(): ByteArray {
  val result = ByteArray(length / 2)

  for (i in result.indices) {
    val d = substring(i * 2, i * 2 + 2)
    result[i] = d.toInt(16).toByte()
  }

  return result
}

private fun StatTest.Result.printResult(testName: String) {
  println("-> Test $testName: $this")
}

private fun List<StatTest.Result>.printResult(testName: String) {
  val minP = this.minBy { it.pValue }.pValue
  val maxP = this.maxBy { it.pValue }.pValue
  val rejected = this.count { !it.accept }
  println("-> Test $testName: p-values range from $minP to $maxP; rejected $rejected out of ${this.count()}")
}

private data class HashX3<T>(
  val message: T,
  val sha2: T,
  val sha3: T,
  val ascon: T,
) {
  fun <R> map(transform: (T) -> R): HashX3<R> =
    HashX3(
      transform(message),
      transform(sha2),
      transform(sha3),
      transform(ascon),
    )

  companion object {
    fun fromRow(row: String): HashX3<String> {
      val data = row.split(',')
      if (data.size != 4) error("Invalid row - need exactly 4 elements")
      return HashX3(data[0], data[1], data[2], data[3])
    }
  }
}
