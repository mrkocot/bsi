package stackelberg

/** Supports up to 16 attacks and 16 defences */
data class ActionSet(private val actionNumber: ULong) {
  fun attacks(game: GameData): Set<String> {
    val alphaRev = game.attacks.keys.sorted().reversed()
    val ret = mutableSetOf<String>()
    var attackNumber = actionNumber / 0x10000U
    for (atk in alphaRev) {
      if (attackNumber % 2U == 1UL) {
        ret.add(atk)
      }
      attackNumber /= 2U
    }
    return ret.toSet()
  }

  fun defences(game: GameData): Set<String> {
    val alphaRev = game.defences.keys.sorted().reversed()
    val ret = mutableSetOf<String>()
    var defenceNumber: ULong = actionNumber % 0x10000U
    for (def: String in alphaRev) {
      if (defenceNumber % 2U == 1UL) {
        ret.add(def)
      }
      defenceNumber /= 2U
    }
    return ret.toSet()
  }

  companion object {
    fun allDefences(game: GameData): List<UInt> =
      (0 until twoPow(game.defences.size)).map { (it % 0x10000).toUInt() }

    fun allActionSets(game: GameData, defence: UInt): List<ActionSet> {
      val attacks = (0 until twoPow(game.attacks.size)).map { (it.toULong() * 0x10000UL) }
      return attacks.map { ActionSet(it + defence) }
    }

    fun onlyDefence(defence: UInt): ActionSet = ActionSet(defence.toULong())

    fun empty(): ActionSet = ActionSet(0UL)
  }
}

private fun twoPow(bits: Int): Long {
  if (bits > 30) error("Too much for positive long")
  var ret = 1L
  repeat(bits) { ret *= 2 }
  return ret
}
