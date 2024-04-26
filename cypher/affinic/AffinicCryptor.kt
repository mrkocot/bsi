package affinic

object AffinicCryptor {
  private fun String.encrypt(a: Int, b: Int): String =
    this.mapLetters { it.ord().ab(a, b).chr() }

  private fun String.decrypt(a: Int, b: Int): String =
    this.mapLetters { it.ord().revAb(a, b).chr() }

  private fun verifyAB(a: Int, b: Int): Boolean =
    a > 0 && b >= 0 && a < 26 && gcd(a, 26) == 1 && b < 26

  private fun solveWithPairs(p1: Pair<Char, Char>, p2: Pair<Char, Char>): Pair<Int, Int>? {
    val a1 = p1.first.ord()
    val a2 = p2.first.ord()
    val b1 = p1.second.ord()
    val b2 = p2.second.ord()
    var diffA = a1 - a2
    var diffB = b1 - b2
    if (diffA < 0) {
      diffA = -diffA
      diffB = -diffB
    }
    if ((diffA % 2 == 0) != (diffB % 2 == 0)) return null // if they have different parities, adding 26 will not help
    while (diffB % diffA != 0) diffB += 26
    val solutionA = diffB / diffA
    val solutionB = (b1 - a1 * solutionA) posMod 26
    return solutionA to solutionB
  }

  private fun testNxN(cypher: String, n: Int): List<String> {
    val results = mutableListOf<String>()
    val upc = cypher.uppercase()
    val counts = PROBS.keys.associateWith { letter -> upc.count { it == letter } }
    for ((a1, a2) in PROBS.getTopN(n).getAllPairs()) {
      for ((b1, b2) in counts.getTopN(n).getAllPairs()) {
        val sol = solveWithPairs(a1 to b1, a2 to b2) ?: continue
        val body = if (verifyAB(sol.first, sol.second)) {
          cypher.decrypt(sol.first, sol.second).also { results.add(it) }
        } else "<Incorrect key>"
//        println("$a1$b1 $a2$b2 a=${sol.first} b=${sol.second}: $body")
      }
    }
    return results
  }

  private fun testUntilSuccessful(cypher: String, goalPlain: String, maxN: Int): Int {
    val goalUpper = goalPlain.uppercase()
    repeat(maxN - 1) {
      val n = it + 2
      val results = testNxN(cypher, n)
      if (results.contains(goalUpper)) return n
    }
    return 999
  }

  private fun Map<Char, Int>.getTopN(n: Int): List<Char> =
    this.entries
      .sortedByDescending { it.value }
      .take(n)
      .map { it.key }

  private fun List<Char>.getAllPairs(): List<Pair<Char, Char>> {
    val res = mutableListOf<Pair<Char, Char>>()
    for (a in this) {
      for (b in this) {
        if (a != b) res.add(a to b)
      }
    }
    return res
  }

  @JvmStatic
  fun main(args: Array<String>) {
    val text1 = "A potato has a lot of starch and other carbohydrates. Potato usually has a light-brown or yellowish skin and is white or yellow inside. If the potato gets light on it, the tuber turns green and will be poisonous."
    val text2 = "Depends"

    val c1 = text1.encrypt(7, 7)
    val c2 = text2.encrypt(7, 7)

    val d1 = c1.decrypt(7, 7)
    val d2 = c2.decrypt(7, 7)

//    val karoCyph = "SKEEWSSGSZIBFGZMHFMGHKJWGSZIBFMBMHGBGSBXWEIKJMOWBIEIZBGZKWBXMBEIKZBS"

    val n1 = testUntilSuccessful(c1, text1, 6)
    val n2 = testUntilSuccessful(c2, text2, 6)

    println("Longer text needed top $n1 letters; shorter needed top $n2 letters")
//    println()
//    testNxN(t2, 3)
//    testNxN(karoCyph, 5)
    println("---")
  }
}

private fun String.mapLetters(operation: (Char) -> Char): String =
  this.uppercase().map{
    if (it.isLetter()) operation(it) else it
  }.joinToString(separator = "")

private fun Char.ord(): Int =
  this.code - 'A'.code

private fun Int.chr(): Char =
  Char(this + 'A'.code)

private fun Int.ab(a: Int, b: Int): Int =
  (a * this + b) posMod  26

private fun Int.revAb(a: Int, b: Int): Int =
  ((this - b) * (a invMod 26)) posMod 26

private infix fun Int.posMod(div: Int): Int =
  (this % div).let { if (it >= 0) it else it + div }

private infix fun Int.invMod(mod: Int): Int {
  var a = this
  var m0 = mod
  var y = 0
  var x = 1

  if (mod == 1) return 0

  while (a > 1) {
    // q is quotient
    val q = a / m0
    var t = m0

    // m is remainder now, process same as
    // Euclid's Algorithm
    m0 = a % m0
    a = t
    t = y

    // Update y and x
    y = x - q * y
    x = t
  }

  // Make x positive
  if (x < 0) x += mod

  return x
}

private val PROBS = mapOf(
  'A' to 82, // 0
  'B' to 15,
  'C' to 28,
  'D' to 43,
  'E' to 127,
  'F' to 22, // 5
  'G' to 20,
  'H' to 61,
  'I' to 70,
  'J' to 2,
  'K' to 8, // 10
  'L' to 40,
  'M' to 24,
  'N' to 67,
  'O' to 75,
  'P' to 19, // 15
  'Q' to 1,
  'R' to 60,
  'S' to 63,
  'T' to 91,
  'U' to 28, // 20
  'V' to 10,
  'W' to 23,
  'X' to 1,
  'Y' to 20,
  'Z' to 1, // 25
)

tailrec fun gcd(a: Int, b: Int): Int {
  if (b == 0) {
    return a
  }
  return gcd(b, a % b)
}
