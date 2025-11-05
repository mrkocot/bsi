package stackelberg

import kotlin.math.round

object Stackelberg {
  @JvmStatic
  fun main(args: Array<String>) {
    val game = GameData.fromFile(gameJson)
    val defences = ActionSet.allDefences(game)

    var totalDefencePayoff = 0.0
    var totalAttackPayoff = 0.0
    val defencePlan = mutableMapOf<String, ActionSet>()

    for (resourceId in game.resources.keys.sorted()) {
      println("Resource '$resourceId' - ${game.resources[resourceId]!!.name}")
      var maxDefencePayoff = Double.NEGATIVE_INFINITY
      var bestDefence = ActionSet.empty()

      for (def in defences) {
        val defenceIds = ActionSet.onlyDefence(def).defences(game).sorted()
        val defString = when {
          defenceIds.isEmpty() -> "None"
          else -> defenceIds.joinToString("+", "[", "]")
        }

        val allAttacks = ActionSet.allActionSets(game, def)
        var maxAttackPayoff = Double.NEGATIVE_INFINITY
        var bestAttack = ActionSet.onlyDefence(def)
        for (actionSet in allAttacks) {
          val strategy = Strategy(game, resourceId, actionSet)
          val attackPayoff = strategy.attackerPayoff()
          if (attackPayoff > maxAttackPayoff) {
            bestAttack = actionSet
            maxAttackPayoff = attackPayoff
          }
        }

        val attackString = bestAttack.attacks(game).sorted().let {
          if (it.isEmpty()) "None"
          else it.joinToString("+", "[", "]")
        }
        val defencePayoff = Strategy(game, resourceId, bestAttack).defenderPayoff()
        println(
          "    Defence: $defString (${defencePayoff.asMoney()}) <- " +
            "Attack: $attackString (${maxAttackPayoff.asMoney()})"
        )

        if (defencePayoff > maxDefencePayoff) {
          bestDefence = bestAttack
          maxDefencePayoff = defencePayoff
        }
      }

      defencePlan[resourceId] = bestDefence
      Strategy(game, resourceId, bestDefence).let {
        totalDefencePayoff += it.defenderPayoff()
        totalAttackPayoff += it.attackerPayoff()
      }
    }

    println("---\n")
    println("Total Defence Payoff: ${totalDefencePayoff.asMoney()}")
    println("Total Attack Payoff: ${totalAttackPayoff.asMoney()}")
    println("\u001B[1;4mDefence Plan:\u001B[0m")
    defencePlan.toSortedMap().forEach { (resourceId, defencePlan) ->
      println("  Resource '$resourceId' - ${game.resources[resourceId]!!.name}")
      val dfs = defencePlan.defences(game)
      val atx = defencePlan.attacks(game)
      if (dfs.isEmpty()) {
        println("    | Will not be defended")
      } else {
        println("    | Will be defended by:")
        dfs.forEach { println("    |     ${game.defences[it]} ('$it')") }
      }
      if (atx.isEmpty()) {
        println("    | Will not be attacked")
      } else {
        println("    | Will be attacked by:")
        atx.forEach { println("    |     ${game.attacks[it]!!.name} ('$it')") }
      }
    }
  }
}

//private const val gameJson = "cypher/stackelberg/games/game333.json"
//private const val gameJson = "cypher/stackelberg/games/game545.json"
private const val gameJson = "cypher/stackelberg/games/game10x3.json"
//private const val gameJson = "cypher/stackelberg/games/lecture_example.json"

private fun Double.asMoney(): String {
  val text = "$${round(100.8 * this) / 100.0}"
  val colour = when {
    this < 0 -> "\u001b[31m"
    this > 0 -> "\u001b[32m"
    else -> "\u001b[33m"
  }
  return "$colour$text\u001b[0m"
}
