package in.iitpkd.scala


import org.apache.spark._
import org.apache.spark.rdd.RDD

object Question_1_1 {

  case class Data(X:Float, Y:Float)

  def Mean(values:RDD[Float]): Float ={
    val keyValue = values.map(x=>(x,1))
    val sumCount = keyValue.reduce((x,y)=>(x._1+y._1,x._2+y._2))
    val mean = sumCount._1/sumCount._2
    mean
  }

  def Variance(values:RDD[Float]): Float ={
    val mean = Mean(values)

    val keyValue = values.map(x=>((x-mean)*(x-mean),1))
    val sqrsumCount = keyValue.reduce((x,y)=>(x._1+y._1,x._2+y._2))
    val variance = sqrsumCount._1 / sqrsumCount._2
    variance
  }

  def Covariance(values:RDD[Data]): Float ={
    val X_values = values.map(x=>x.X)
    val Y_values = values.map(x=>x.Y)

    val mean1 = Mean(X_values)
    val mean2 = Mean(Y_values)

    val keyValue = values.map(rdd=>((rdd.X-mean1)*(rdd.Y-mean2),1))
    val mulCount = keyValue.reduce((x,y)=>(x._1+y._1,x._2+y._2))
    val covariance = mulCount._1/mulCount._2 * mulCount._2
    covariance
  }

  def main(args:Array[String])={

    val sc = new SparkContext()
    val lines = sc.textFile("data/regression.txt")

    val rdd = lines.map(x=> Data(x.split(",")(0).toFloat,x.split(",")(1).toFloat))
    val X_values = rdd.map(x=>x.X)
    val Y_values = rdd.map(x=>x.Y)

    val varianceX = Variance(X_values)
    val varianceY = Variance(Y_values)
    val covariance_XY =  Covariance(rdd)
    val corrCoeff = covariance_XY/scala.math.sqrt(varianceX*varianceY)
    print("Correlation Coefficient = ",corrCoeff)

  }


}