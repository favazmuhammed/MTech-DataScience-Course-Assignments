package in.iitpkd.scala
import org.apache.spark._
import org.apache.spark.rdd.RDD
import org.apache.log4j._

import scala.util.matching.Regex


object Exercise1{

  // defining RDD[Log] class
  case class Log(ProjectCode:String, PageTitle:String, PageHits:Int, PageSize:Long)

  // function for take input as RDD[String] and output as RDD[Log]
  def ParseLines(line:String):Log={
    val field = line.split(" ")                    //split each line on " "
    Log(field(0),field(1),field(2).toInt,field(3).toLong)
  }

  def Question1(rdd:RDD[Log]): Unit ={
    val first_15 =  rdd.take(15)    //take first 15 elements

    // print headers of each field
    println("ProjectCode"+"\t\t"+"PageTitle"+" "*(60-"PageTitle".length())+"PageHits"+"\t"+"PageSize")
    println("-"*96)
    //print records
    for (temp <- first_15){
      println(temp.ProjectCode+"\t\t\t\t"+temp.PageTitle+" "*(60-temp.PageTitle.length())+temp.PageHits+"\t\t\t"+temp.PageSize)
    }
  }

  def Question2(rdd:RDD[Log]): Unit ={
    val rdd_ = rdd.map(x=> (x.PageTitle,1))
    val values = rdd_.values
    val count = values.reduce((x,y)=>x+y)
    println(s"Number of records: $count")
  }

  def Question3(rdd:RDD[Log]):Float ={
    val rdd_ = rdd.map(x=> (x.PageTitle,x.PageSize))
    val maxPages = rdd_.values.max()
    val minPages = rdd_.values.min()
    val totals = rdd_.mapValues(x=>(x,1)).values.reduce((x,y)=>(x._1+y._1,x._2+y._2))
    val avgPages = totals._1/totals._2

    println(s"Maximum number of pages: $maxPages")
    println(s"Minimum number of pages: $minPages")
    println(s"Average number of pages $avgPages")

    avgPages   //return average page size
  }

  def Question4(rdd:RDD[Log]): Unit ={
    val rdd_ = rdd.map(x=> (x.PageTitle,x.PageSize))
    val maxPages = rdd_.values.max()
    val recordMaxPages = rdd.filter(x=>x.PageSize==maxPages)

    val results = recordMaxPages.collect()
    println("ProjectCode"+"\t\t"+"PageTitle"+" "*(20-"PageTitle".length())+"PageHits"+"\t"+"PageSize")
    println("-"*60)
    for (record <- results){
      println(record.ProjectCode+"\t\t\t"+record.PageTitle+" "*(20-record.PageTitle.length())+record.PageHits+"\t\t"+record.PageSize)
    }
  }

  def Question5(rdd:RDD[Log]): Unit ={
    val rdd_ = rdd.map(x=> (x.PageTitle,x.PageHits))
    val maxPageHits = rdd_.values.max()
    val popular = rdd.filter(x=> x.PageHits==maxPageHits)
    val maxPageInPopular = popular.map(x=>(x.PageTitle,x.PageSize)).values.max()
    val popularMaxPage = popular.filter(x=>x.PageSize==maxPageInPopular)
    val results = popularMaxPage.collect()
    println("ProjectCode"+"\t\t"+"PageTitle"+" "*(20-"PageTitle".length())+"PageHits"+"\t"+"PageSize")
    println("-"*60)
    for (record <- results){
      println(record.ProjectCode+"\t\t\t"+record.PageTitle+" "*(20-record.PageTitle.length())+record.PageHits+"\t\t"+record.PageSize)
    }
  }
  def Question6(rdd:RDD[Log]): Unit ={
    val maxTitleLength = rdd.map(x=>(x.PageTitle,x.PageTitle.length)).values.max()
    val maxLengthRecords = rdd.filter(x=>x.PageTitle.length==maxTitleLength)
    val results = maxLengthRecords.collect()

    for (record <- results){
      println(record.PageTitle)
    }
  }

  def Question7(rdd:RDD[Log],avgPages:Float): Unit ={
    // take input as RDD of all records and average page size
    val rddNew = rdd.filter(x=>x.PageSize>=avgPages)
    println(s"No of records with page size more than average page size: ${rddNew.count()}")
  }

  def Question8(rdd:RDD[Log]): Unit ={
    val newRDD = rdd.map(x=>(x.ProjectCode,x.PageHits))
    val totalProjectHits=newRDD.reduceByKey((x,y)=>x+y)
    val sortedTotalProjectHits = totalProjectHits.sortByKey(ascending = false)
    val results = sortedTotalProjectHits.collect()

    //print projects and their total views
    for (result <- results){
      println(result)
    }
  }

  def Question9(rdd:RDD[Log]): Unit ={
    val newRDD = rdd.map(x=>(x.ProjectCode,x.PageHits))
    val ProjectHits=newRDD.groupByKey()
    val results = ProjectHits.collect()

    for(result <- results){
      println(s"ProjectCode: ${result._1}")
      val values = result._2.toList
      val sortedValues = values.sorted.reverse
      print("Best views:")
      for (i <- 0 to 9){
        if (i < sortedValues.length)
        {print(s"\t${sortedValues(i)}")}
      }
      println("\n"+"-"*40)
    }
  }

  def Question10(rdd:RDD[Log]): Unit ={
    // filter the records having title length > 2 and first 3 letters = "The"
    val newRDD = rdd.filter(x=>x.PageTitle.length > 2 && x.PageTitle.substring(0,3)=="The")
    println(s"No of records with title starting with 'The': ${newRDD.count()}")
    // filter the records ProjectCode not equals to "en"
    val enRDD = newRDD.filter(x=>x.ProjectCode != "en")
    println(s"No of records starting with 'The' but not English project: ${enRDD.count()}")
  }

  def Question11(rdd:RDD[Log]): Unit ={
    val rdd_ = rdd.filter(x=>x.PageHits==1)
    val percentage = rdd_.count()*100/rdd.count()
    val formattedPercentage = f"$percentage%.2f"
    println(s"Percentage of pages that have only received a single page: $formattedPercentage")
  }
  def Question12(rdd:RDD[Log]): RDD[String] ={
    //define regular expressions for cleaning the texts
    val pattern1: Regex = """[:/]""".r
    val pattern2: Regex = """[^a-z0-9_]""".r

    //split the titles and split with '_'
    val tokens= rdd.map(x=>(x.ProjectCode, pattern2.replaceAllIn(pattern1.replaceAllIn(x.PageTitle.toLowerCase,"_"),"").split("_")))
      .flatMapValues(x => x).values
    println(s"Number of unique words: ${tokens.distinct().count()}")

    tokens    //return tokens
  }

  def Question13(tokens:RDD[String]): Unit ={
    // function will take all tokens from titles
    val tokensCount = tokens.map(x=>(x,1)).reduceByKey((x,y)=>x+y).sortBy(_._2,false)
    val results = tokensCount.collect()
    println(s"Most occurring title term: '${results.head._1}', with count: ${results.head._2}")
  }


  def main(args:Array[String]): Unit ={

    Logger.getLogger("org").setLevel(Level.ERROR)
    //initialize spark context
    val sc = new SparkContext("local[*]","Question1")
    //read the data
    val data = sc.textFile("pagecounts-20160101-000000_parsed.out")

    //convert RDD[String] to RDD[Log]
    val rdd = data.map(ParseLines)

    // Executing Questions
    Question1(rdd)
    Question2(rdd)
    val avgPages = Question3(rdd)
    Question4(rdd)
    Question5(rdd)
    Question6(rdd)
    Question7(rdd,avgPages)
    Question8(rdd)
    Question9(rdd)
    Question10(rdd)
    Question11(rdd)
    val tokens = Question12(rdd)
    Question13(tokens)

  }
}