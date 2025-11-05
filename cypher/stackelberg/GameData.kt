package stackelberg

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.io.File

data class GameData(
  val resources: Map<String, Resource>,
  val defences: Map<String, String>,
  val attacks: Map<String, Attack>,
) {
  data class Resource(
    val name: String,
    val value: Double,
    val attackGain: Double,
    val defenseCost: Map<String, Double>,
    val attackCost: Map<String, Double>,
  )

  data class Attack(
    val name: String,
    val chance: Map<String, Double>,
  )

  companion object {
    fun fromFile(path: String): GameData {
      val mapper = jacksonObjectMapper()
      val file = File(path)
      val content = file.readText()

      return mapper.readValue(content, GameData::class.java)
    }
  }
}
