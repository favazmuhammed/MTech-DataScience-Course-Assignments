// kmeans-train.txt -> [income, age] vector  -. use kmeans clustering to cluster this dataset into 5 clusters.

// kmeans-test.txt -> for testing this set, we used this tuples present inside this txt file.
// (clusterid, [vector of features])


package in.iitpkd.scala

import org.apache.spark.streaming.{Seconds,StreamingContext}
import org.apache.spark.storage.StorageLevel
import org.apache.spark.mllib.linalg.Vectors
import org.apache.spark.mllib.regression.LabeledPoint
import org.apache.spark.mllib.clustering.StreamingKMeans

/** Example of using streaming K-Means clustering to cluster people by income
 * and age into 5 clusters
 */

object StreamingKMeans{
  def setupLogging():Unit={
    import org.apache.log4j.{Level,Logger}
    val rootLogger=Logger.getRootLogger
    rootLogger.setLevel(Level.ERROR)
  }

  def main(args:Array[String])
  {

    //Create the context with a 1 second batch size
    val ssc = new StreamingContext("local[*]","StreamingKMeans",Seconds(1))
    setupLogging()

    //Create a socket stream to listen for training data on port 9999
    //This will listen for [income,age] data (or anything else) that we want to cluster
    val trainingLines=ssc.socketTextStream("127.0.0.1",9999,StorageLevel.MEMORY_AND_DISK_SER)

    //Add another stream that listens for test data on port 7777
    //This expects(cluster ID,[income,age]) lines,but in the real world you wouldnot know
    //the "correct" clustering ahead of time.
    val testingLines=ssc.socketTextStream("127.0.0.1",7777,StorageLevel.MEMORY_AND_DISK_SER)

    //Convert input data to vectors and LabeledPoints for the MLMib functions we will use
    val trainingData=trainingLines.map(Vectors.parse).cache()   // training data use for the training model.
    val testData=testingLines.map(LabeledPoint.parse)   // testing data evaluate the performance.

    //Just so we see something happen when training data is received
    trainingData.print()

    //Build a K-Means clustering model for 5 clusters and 2 features (age and Income)
    val model = new StreamingKMeans()
      .setK(5)
      .setDecayFactor(1.0)
      .setRandomCenters(2,0.0)

    model.trainOn(trainingData)  // train the model using training data.

    //And as test data is received,we will keep refining our clustering model and printing out the
    //results.In the real world,we would just use predictionOn() which only expects feature data ,as yo
    //wouldn't know the "correct" clustering ahead of time.But in this case we print the cluster
    //we assigned in the test data alongside the predicted cluster ID's.The ID's themselves do not
    //to match,but the clustering should be more or less consistent.
    model.predictOnValues(testData.map(lp=>(lp.label.toInt,lp.features))).print()
// printed out the predictor values.

    //Kick it off
    ssc.checkpoint("C:/checkpoint/")
    ssc.start()
    ssc.awaitTermination()
  }
}

//ncat -kl 7777 < kmeans-test.txt
//ncat available in nmap.org

