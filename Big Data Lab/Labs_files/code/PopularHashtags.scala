package in.iitpkd.scala

import org.apache.spark.streaming._
import org.apache.spark.streaming.twitter._
/*Listens to a stream of tweets and keeps track of the most popular hashtags over a 5 minute window*/

object PopularHashtags{
  /*Make sure only ERROR messages are logged to avoid log spam*/

  def setupLogging(): Unit={
    import org.apache.log4j.{Level,Logger}
    val rootLogger = Logger.getRootLogger
    rootLogger.setLevel(Level.ERROR)
  }

  /*Configures Twitter service credentials using twitter.txt in the main workspace*/
  def setupTwitter():Unit={
    import scala.io.Source

    val lines =Source.fromFile("data/twitter.txt")
    for(line<-lines.getLines)
    {
      val fields = line.split(" ")
      if(fields.length ==2){
        System.setProperty("twitter4j.oauth." + fields(0), fields(1))
      }
    }
    lines.close()
  }

  /*Our main function where the action happens */

  def main(args: Array[String]){
    //Configure twitter credentials using twitter.txt
    setupTwitter()
    //Set up a spark Streaming context named "PopularHashTags" that runs locally using
    //all CPU cores and one-second batches of data

    val ssc= new StreamingContext("local[*]","PopularHashtags", Seconds(1))


    setupLogging()

    //Create a Dstream from twitter using our streaming context
    val tweets = TwitterUtils.createStream(ssc, None)

    //Now extract the text of each status update into Dstreams using map()

    val statuses = tweets.map(status => status.getText)

    //BLow out each word into a new Dstream

    val tweetwords = statuses.flatMap(tweetText => tweetText.split(" "))

    //Now eliminate anything that's not a hashtag
    val hashtags = tweetwords.filter(word => word.startsWith("#"))

    //Map each hashtag to a key/value pair of (hashtag,1) so we count them
    val hashtagKeyValues = hashtags.map(hashtag => (hashtag, 1))

    //Now count them up over a 5 minute(300) window sliding every one second
    val hashtagCounts = hashtagKeyValues.reduceByKeyAndWindow((x,y) => x+y,(x,y) => x-y, Seconds(300), Seconds(1))

    //Sort the results by the count values
    val sortedResults = hashtagCounts.transform(rdd => rdd.sortBy(x => x._2, ascending = false))

    //Print the top 10
    sortedResults.print

    //Set a checkpoint directory and kick it all off
    //I could watch this allday!

    ssc.checkpoint("C:/checkpoint/")
    ssc.start()
    ssc.awaitTermination()
  }
}




/*
Time: 1650218213000 ms
-------------------------------------------
(#امپورٹڈ_حکومت_نامنظور,34)
(#alsancak,12)
(#karşıyaka,7)
(#bornova,6)
(#ſanalſex,6)
(#ſanalſhow,5)
(#ankaratraveﬅi,4)
(#PTD_ON_STAGE_LV,4)
(#adanaesc,4)
(#BNB,4)
...

-------------------------------------------
Time: 1650218214000 ms
-------------------------------------------
(#امپورٹڈ_حکومت_نامنظور,34)
(#alsancak,12)
(#karşıyaka,7)
(#bornova,6)
(#ſanalſex,6)
(#ſanalſhow,5)
(#ankaratraveﬅi,4)
(#PTD_ON_STAGE_LV,4)
(#adanaesc,4)
(#BNB,4)
...

-------------------------------------------
Time: 1650218215000 ms
-------------------------------------------
(#امپورٹڈ_حکومت_نامنظور,34)
(#alsancak,12)
(#karşıyaka,7)
(#bornova,6)
(#ſanalſex,6)
(#ſanalſhow,5)
(#ankaratraveﬅi,4)
(#PTD_ON_STAGE_LV,4)
(#adanaesc,4)
(#BNB,4)
...

-------------------------------------------
Time: 1650218216000 ms
-------------------------------------------
(#امپورٹڈ_حکومت_نامنظور,34)
(#alsancak,12)
(#karşıyaka,7)
(#bornova,6)
(#ſanalſex,6)
(#ſanalſhow,5)
(#ankaratraveﬅi,4)
(#PTD_ON_STAGE_LV,4)
(#adanaesc,4)
(#BNB,4)
...

-------------------------------------------
Time: 1650218217000 ms
-------------------------------------------
(#امپورٹڈ_حکومت_نامنظور,34)
(#alsancak,12)
(#karşıyaka,7)
(#bornova,6)
(#ſanalſex,6)
(#ſanalſhow,5)
(#ankaratraveﬅi,4)
(#PTD_ON_STAGE_LV,4)
(#adanaesc,4)
(#BNB,4)
...

-------------------------------------------
Time: 1650218218000 ms
-------------------------------------------
(#امپورٹڈ_حکومت_نامنظور,34)
(#alsancak,12)
(#karşıyaka,7)
(#bornova,6)
(#ſanalſex,6)
(#ſanalſhow,5)
(#ankaratraveﬅi,4)
(#PTD_ON_STAGE_LV,4)
(#adanaesc,4)
(#BNB,4)
...
*/