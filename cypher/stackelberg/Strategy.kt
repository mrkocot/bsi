package stackelberg

class Strategy(
  private val game: GameData,
  private val resourceId: String,
  private val actions: ActionSet,
) {
  fun defenderPayoff(): Double {
    val gain = chanceItWorks() * game.resources[resourceId]!!.value
    return gain - defenceCost()
  }

  fun attackerPayoff(): Double {
    val gain = chanceItBroke() * game.resources[resourceId]!!.attackGain
    return gain - attackCost()
  }

  private fun chanceItWorks(): Double {
    val attacks = actions.attacks(game)
    val defence = actions.defences(game)
    return if (attacks.isEmpty()) {
      1.0  // no attacks have been tried, nothing happened
    } else if (defence.isEmpty()) {
      0.0  // no defence was active while some attacks were tried, so attackers succeeded
    } else {
      var allAttacksFailed = 1.0
      for (a in attacks) {
        val chances = game.attacks[a]!!.chance
        val thisAttackSucceeded = defence.map { chances[it]!! }.fold(1.0) { acc, chance -> acc * chance }
        allAttacksFailed *= (1.0 - thisAttackSucceeded)
      }
      allAttacksFailed  // product of all attacks' fail chances
    }
  }

  private fun chanceItBroke(): Double = 1.0 - chanceItWorks()

  private fun defenceCost(): Double {
    val activeDefences = actions.defences(game)
    return activeDefences.sumOf { game.resources[resourceId]!!.defenseCost[it]!! }
  }

  private fun attackCost(): Double {
    val activeAttacks = actions.attacks(game)
    return activeAttacks.sumOf { game.resources[resourceId]!!.attackCost[it]!! }
  }
}

