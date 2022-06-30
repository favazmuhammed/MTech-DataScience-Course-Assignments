package in.iitpkd.scala
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions._
import org.apache.log4j._


object WordCountDataSet {
  case class Book(value: String)
  def main(args: Array[String]): Unit ={
    Logger.getLogger("org").setLevel(Level.ERROR)
    val spark = SparkSession
      .builder
      .appName("WordCount")
      .master("local[*]")
      .getOrCreate()

    import spark.implicits._
    val input = spark.read.text("data/The_Hunger_Games.txt").as[Book]

    val words = input
      .select(explode(split($"value", "\\W+")).alias("word"))
      .filter($"word" =!= "")

    val lowercaseWords = words.select(lower($"word").alias("word"))
    val wordCount = lowercaseWords.groupBy("word").count()

    val wordCountSorted = wordCount.sort("count")

    wordCountSorted.show(wordCountSorted.count.toInt)

    //Another way to do the same
    val bookRDD = spark.sparkContext.textFile("data/The_Hunger_Games.txt")
    val wordsRDD = bookRDD.flatMap(x => x.split("\\W+"))
    val wordsDS = wordsRDD.toDS()

    val lowercaseWordsDS =wordsDS.select(lower($"value").alias("word"))
    val wordCountDS = lowercaseWordsDS.groupBy("word").count()
    val wordsCountSortedDS = wordCountDS.sort("count")

    wordsCountSortedDS.show(wordsCountSortedDS.count.toInt)

    spark.close()

  }
}
