package in.iitpkd.scala

import org.apache.spark._
import org.apache.log4j._


object FriendsByAge {
  def parseLine(line:String):(Int,Int)={
    val fields = line.split(",")
    val age = fields(2).toInt
    val numFriends = fields(3).toInt
    (age,numFriends)
  }

  def main(args:Array[String]){
    Logger.getLogger("org").setLevel(Level.ERROR)
    val sc = new SparkContext(master="local[*]",  appName = "FriendsByAge")
    val lines = sc.textFile("data/friends-noheader.csv")
    val rdd = lines.map(parseLine)
    val totalsByAge = rdd.mapValues(x=>(x,1)).reduceByKey((x,y)=>(x._1+y._1,x._2+y._2))
    val avgByAge = totalsByAge.mapValues(x=>x._1/x._2)
    val results = avgByAge.collect()
    results.sorted.foreach(println)
  }
}