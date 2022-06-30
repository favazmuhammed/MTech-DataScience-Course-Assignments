package in.iitpkd.scala
import org.apache.spark._
import org.apache.log4j._
import scala.math.min

object minTemperature {
  def parseLine(line:String)={
    val fields = line.split(",")
    val stationID = fields(0)
    val entryType = fields(2)
    val temperature = fields(3).toFloat * 0.1f
    (stationID,entryType,temperature)
  }

  def main(args:Array[String]): Unit ={
    Logger.getLogger("org").setLevel(Level.ERROR)
    val sc = new SparkContext(master="local[*]",  appName = "minTemperature")
    val lines = sc.textFile("data/weather.csv")
    val parsedLines = lines.map(parseLine)
    val minTemp = parsedLines.filter(x=>x._2=="TMIN")
    val stationTemp =  minTemp.map(x=>(x._1,x._3.toFloat))
    val minTempByStation = stationTemp.reduceByKey((x,y)=>min(x,y))
    val results = minTempByStation.collect()

    for (result <- results.sorted){
      val station = result._1
      val temp = result._2
      val formattedTemp = f"$temp%.2f C"
      println(s"$station minimum temperature: $formattedTemp")
    }

  }

}