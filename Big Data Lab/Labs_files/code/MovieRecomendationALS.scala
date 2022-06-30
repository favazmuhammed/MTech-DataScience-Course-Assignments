package in.iitpkd.scala

import org.apache.spark.sql.{Row,SparkSession}
import org.apache.spark.ml.recommendation._
import org.apache.spark.sql.types.{IntegerType, LongType, StringType, StructType}
import org.apache.log4j._
import scala.collection.mutable

object MovieRecomendationALS {

  case class MovieNames(movieId: Int, movieTitle: String)
  case class Ratings(userID: Int, movieID: Int, rating: String)

  def getMovieName(movieName: Array[MovieNames], movieID: Int): String ={
    val result = movieName.filter(_.movieId == movieID)(0)
    result.movieTitle
  }

  def main(args: Array[String]): Unit ={
    Logger.getLogger("org").setLevel(Level.ERROR)
    val spark = SparkSession
      .builder
      .appName("MovieRecomendation")
      .master("local[*]")
      .getOrCreate()

    println("Loading Movie Names...")

    val movieNamesSchema = new StructType()
      .add("movieID", IntegerType, nullable = true)
      .add("movieTitle", StringType, nullable = true)

    val moviesSchema = new StructType()
      .add("userID", IntegerType, nullable = true)
      .add("movieID", IntegerType, nullable = true)
      .add("rating", IntegerType, nullable = true)
      .add("timestamp", LongType, nullable = true)

    import spark.implicits._
    val names = spark.read
      .option("sep","|")
      .option("charset", "ISO-8859-1")
      .schema(movieNamesSchema)
      .csv("ml-100k/u.item")
      .as[MovieNames]

    val namesList = names.collect()

    val ratings = spark.read
      .option("sep","\t")
      .schema(moviesSchema)
      .csv("ml-100k/u.data")
      .as[Ratings]

    println("Training the Recommendation model...")

    val als = new ALS()
      .setMaxIter(5)
      .setRegParam(0.01)
      .setUserCol("userID")
      .setItemCol("movieID")
      .setRatingCol("rating")

    val model = als.fit(ratings)

    //get top 10 movies

    val userID :Int = args(0).toInt
    val user = Seq(userID).toDF("userID")
    val recom = model.recommendForUserSubset(user, 10)

    println("Top 10 recommended movies for user ID "+ userID + ":")

    for(userRecs <- recom){
      val myRecs = userRecs(1) //first col is userID, second is recs
      val temp =  myRecs.asInstanceOf[mutable.WrappedArray[Row]]

      for(rec <- temp){
        val movie = rec.getAs[Int](0)
        val rating = rec.getAs[Float](1)
        val movieName = getMovieName(namesList, movie)

        println(movieName, rating)
      }
    }

    spark.close()
  }
}
