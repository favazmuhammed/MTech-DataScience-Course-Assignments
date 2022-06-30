package in.iitpkd.scala


import org.apache.spark._
import org.apache.spark.sql._

object Question_2_2 {
  case class Names(id:Int, name:String)

  def main(args:Array[String]): Unit ={

    val sc = new SparkContext()
    val lines = sc.textFile("data/Marvel-names.txt")

    val rdd = lines.map(x=> Names(x.split(",")(0).toInt,x.split(",")(1)))

    val firstName = rdd.map(line => (line.name.split("[/\,|]")(-1),1))
    val nameCount = firstName.reduceByKey((x,y)=>x+y)
    val nameSort = nameCount.sortByKey(ascending = false)
    println(nameSort.collect().head)
  }



}