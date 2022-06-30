package in.iitpkd.scala
import in.iitpkd.scala.Exercise1.ParseLines
import org.apache.spark._
import org.apache.spark.sql._
import org.apache.log4j._

import scala.util.matching.Regex

object Exercise2 {

  case class Log(ProjectCode: String, PageTitle: String, PageHits: Int, PageSize: Long)

  def main(args:Array[String]): Unit ={
    Logger.getLogger("org").setLevel(Level.ERROR)
    val sc = new SparkContext("local[*]","Question1")
    val data = sc.textFile("pagecounts-20160101-000000_parsed.out")

    //convert RDD[String] to RDD[Log]
    val rdd = data.map(ParseLines)

    val spark = SparkSession
      .builder
      .appName("SparkSQL")
      .master("local[*]")
      .getOrCreate()

    val df = spark.createDataFrame(rdd)
      .toDF("ProjectCode", "PageTitle","PageHits","PageSize")

    // show first 10 entries
    //df.show(10)

    // register the DataFrame as a SQL temporary view
    df.createTempView("projects")

    //Question-3
    val df_qn3 = spark.sql("SELECT MIN(PageSize),MAX(PageSize),AVG(PageSize) FROM projects")
    df_qn3.show()

    //Question-5
    val df_qn5 = spark.sql("SELECT * FROM projects WHERE PageHits == (SELECT MAX(PageHits) FROM projects)")
    df_qn5.show()

    //Question-7
    val df_qn7 = spark.sql("SELECT * FROM projects WHERE PageSize >= (SELECT AVG(PageSize) FROM projects)")
    df_qn7.show()

    // Question-12
    val df_qn12 = spark.sql("SELECT PageTitle FROM projects")
    val titles_rdd = df_qn12.rdd  //convert DataFrame to rdd
    //define regular expressions for cleaning the texts
    val pattern1: Regex = """[:/]""".r
    val pattern2: Regex = """[^a-z0-9_]""".r

    //split the titles and split with '_'
    val tokens= titles_rdd.map(x=> ("token",pattern2.replaceAllIn(pattern1.replaceAllIn(x.toString().toLowerCase,"_"),"")
      .split("_"))).flatMapValues(x => x).values
    println(s"Number of unique words: ${tokens.distinct().count()}")

    //Question - 13
    // count number of occurring of each token and sort it
    val tokensCount = tokens.map(x=>(x,1)).reduceByKey((x,y)=>x+y).sortBy(_._2,false)
    val results = tokensCount.collect()
    println(s"Most occurring title term: '${results.head._1}', with count: ${results.head._2}")

    spark.stop()

  }
}