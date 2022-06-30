package in.iitpkd.scala

import org.apache.spark.streaming._
import org.apache.spark.streaming.twitter._

object PopularHashtags {

  def setupLogging(): Unit ={
    import org.apache. log4j.{Level, Logger}
    val rootLogger = Logger.getRootLogger
    rootLogger.setLevel(Level.ERROR)
  }

  def setupTwitter(): Unit = {
    import scala.io.Source
    val lines = Source.fromFile("data/twitter.txt")
    for (line <- lines.getLines) {
      val fields = line.split(" ")
      if (fields.length == 2) {
        System.setProperty("twitter4j.oauth." + fields(0), fields(1))
      }
    }
    lines.close()
  }

  def main(args: Array[String]): Unit ={
    setupTwitter()

    val ssc = new StreamingContext(
      "local[*}",
      "PopularHashtags",
      Seconds(1)
    )

    setupLogging()

    val tweets = TwitterUtils.createStream(ssc, None)
    val statuses = tweets.map(status => status.getText)
    val tweetWords = statuses.flatMap(tweetText => tweetText.split(" "))
    val hashtags = tweetWords.filter(word => word.startsWith("#"))
    val hashtagKeyValues = hashtags.map(hashtag => (hashtag,1))
    val hashtagCounts = hashtagKeyValues.reduceByKeyAndWindow(
      (x,y) => x+y, (x,y) => x-y, Seconds(300), Seconds(1)
    )

    // val hashtagCounts = hashtagKeyValues.reduceByKeyAndWindow(
    //      _ + _, _ - _, Seconds(300), Seconds(1)
    //    )

    val sortedCounts = hashtagCounts.transform(rdd => rdd.sortBy(x => x._2, ascending = false))
    sortedCounts.print()

    ssc.checkpoint("C:/checkpoint/")
    ssc.start()
    ssc.awaitTermination()

  }
}