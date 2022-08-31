
//2 Variables, conditionals and functions

// 2.1 Variable definitions
val x = 42
val y: Int = 50

// 2.2 Conditionals
println(x+" is "+(if (x%2 ==0) {"even"} else {"odd"}))

//2.3 Function definitions
def increment(x:Int):Int = x+1
def square(x:Int):Int = x*x
def double(x:Int):Int = x*2

println("Square of "+x+" = "+square(x))

// recursive functions
def factorial(n: Int): Int =
  if (n == 0) { 1 } else { n * factorial(n-1) }


val y = 10
println("factorial of "+y+" = "+ factorial(y))


def power(x: Int, n: Int): Int =
  if (n == 0) { 1 } else { x * power(x,n-1) }

val a = power(3,2)
println(a)

// factorial function in different form
def factorial1(n: Int): Int = {
  val m = n-1 ; if (n == 0) { 1 } else { n * factorial1(m) }
}


def factorial2(n:Int):Int = {
  val m = n - 1
  if (n==0) {1} else {n*factorial2(m)}
}



def factorial3(n:Int):Int = {
  val m = n - 1
  if (n==0){
    return 1
  } else{
    return n*factorial3(m)
  }
}

val x = factorial1(5)
val y = factorial2(5)
val z = factorial3(5)

println(x,y,z)

//Exercise 1. Define a function p: (Int,Int) => Int such that
// p(x,y) is the value of the polynomial x**2 + 2xy + y**3 -1
//for the given x and y.

def p(x:Int, y:Int):Int = x*x*x + 2*x*y + y*y*y - 1

val result = p(2,3)
println(result)

//Exercise 2: Define a function sum: Int => Int such that sum(n) is the sum of
// the numbers 0, 1, . . . , n. For example, sum(10) = 55.

def sum(n:Int): Int = if (n >=0) {n + sum(n-1)} else{0}

val s = sum(10)
println(s)




//3 Pairs and Tuples
//3.1 Constructing pairs and tuples

val p = (1,2,3)

val p1 = p._1
println(p1)

//Exercise 3. Write a function cycle: (Int,Int,Int) => (Int,Int,Int) that takes a
// triple of integers and “cycles through them”, moving the first component to
// he end and the other two forward, e.g. cycle((1,2,3)) = (2,3,1).
def cycle(x:(Int,Int,Int)): (Int,Int,Int) = (x._2,x._3,x._1)

val x = cycle((1,2,3))
println(x)

//4 Pattern matching
//4.1 Match/case

def nameFromNum(presidentNum: Int): String = presidentNum match {
  case 41 => "George H. W. Bush"
  case 42 => "Bill Clinton"
  case 43 => "George W. Bush"
  case 44 => "Barack Obama"
  case 45 => "Donald J. Trump"
}
println("The current US president is: " + nameFromNum(45))

def numFromName(presidentName: String): Int =
  presidentName match {
    case "George H. W. Bush" => 41
    case "Bill Clinton" => 42
    case "George W. Bush" => 43
    case "Barack Obama" => 44
    case "Donald J. Trump" => 45
  }

println("Barack Obama is the " + numFromName("Barack Obama") + "th US president")


//Exercise 4: Define a function suffix: Int => String that defines the appropriate suffix
// to use a number as an “ordinal number”. The suffix function should just return the
// suffix, not the number

def suffix(n: Int):String =
  if (n%10 == 1 && n%100 != 11){"st"}
  else if (n%10 == 2 && n%100 != 12){"nd"}
  else if (n%10 == 3 && n%100 != 13){"rd"}
  else {"th"}


println(112+suffix(112))
println(21+suffix(21))
println(122+suffix(122))
println(43+suffix(43))


//Exercise 5. Fill in the definition of favouriteColour above;
// if your favourite colour is not one of the available case classes, add it.

abstract class colour
case class Red() extends colour
case class Blue() extends colour
case class Green() extends colour

def favouriteColour(c: colour): Boolean = c match {
  case Red() => false
  case Blue() => true
  case Green() => false
}


println(favouriteColour(Red()))


abstract class Shape
case class Circle(r: Double, x: Double, y: Double) extends Shape
case class Rectangle(llx: Double, lly: Double, w:Double, h:Double) extends Shape

def center(s: Shape): (Double,Double) = s match {
  case Rectangle(llx,lly,w,h) => (llx+w/2, lly+h/2)
  case Circle(r,x,y) => (x,y)
}

println(center(Rectangle(10,10,1,2)))


//Exercise 6. Define a function boundingBox that takes a Shape and computes the
// smallest Rectangle containing it. (That is, a rectangle’s bounding box is itself;
// a circle’s bounding box is the smallest square that covers the circle.)

def boundingBox(s:Shape):(Double,Double,Double,Double) = s match {
  case Rectangle(llx,lly, w, h) => (llx,lly,w,h)
  case Circle(r,x,y) => (x-r,y-r,2*r,2*r)
}

println(boundingBox(Rectangle(0,0,5,5)))
println(boundingBox(Circle(10,0,0)))


//Exercise 7. Define a function mayOverlap that takes two Shapes and determines whether
// their bounding boxes overlap. (For fun, you might enjoy writing an exact overlap
// test, using mayOverlap to eliminate the easy cases.)

def overlap(interval1:(Double,Double), interval2:(Double,Double)):Boolean = {
  // helper function take two intervals and return its overlap or not
  if ((interval2._1 > interval1._1) && (interval2._1<interval1._2)){true}
  else if ((interval1._1 > interval2._1) && (interval1._1<interval2._2)){true}
  else {false}
}

def mayOverlap(s1:Shape, s2:Shape): Boolean ={
  // bounding box of each shapes
  val rect1 = boundingBox(s1)
  val rect2 = boundingBox(s2)

  // finding intervals of each rectangles
  val x1 = (rect1._1, rect1._1+rect1._3)
  val y1 = (rect1._2, rect1._2+rect1._4)
  val x2 = (rect2._1, rect2._1+rect2._3)
  val y2 = (rect2._2, rect2._2+rect2._4)

  if (overlap(x1,x2) || overlap(y1,y2)) { true } else {false}
}

println(mayOverlap(Circle(5,0,0), Rectangle(10,10,5,4)))
println(mayOverlap(Circle(5,0,0), Rectangle(0,0,5,4)))





//5 Higher-order Functions and Lists
//5.1 Anonymous and Higher-Order Functions


//Exercise 8. Define the function compose1 that takes two functions and composes them:

def compose1(x:Int,y:Int, f:(Int,Int)=> Int, g:Int => Int): Int ={g(f(x,y))}

def sum(x:Int, y:Int):Int = {x+y}
def squareIt(x:Int):Int = {x*x}


println(compose1(2,3,sum,squareIt))

def compose2[A,B,C](f: A => B, g : B => C)(x:A) ={g(f(x))}

def f(x:Int):Int={2*x}
def g(x:Int):Int=(x*x)

println(compose2(f,g)(3))

//val anonInc = {x:Int => x+1}
//val anonAdd = {x:Int => {y:Int => x+y}}

//Exercise 9. Using anonymous functions, define the function compose that takes two
// functions and composes them

def compose[A,B,C](f: A => B, g : B =>C) = {
  x : A =>{val y = f(x);g(y)}
}

println(compose(f,g)(3))

//Exercise 10. Define two expressions e1, e2 such that
//compose[Int,String,Boolean](e1,e2)

def e1(x:Int):String =
  if (x>10){"x greater than 10"} else {"x less than 10"}
def e2(s:String):Boolean=
  if (s.length() > 10) {true} else {false}

compose(e1,e2) //val res18: Int => Boolean = <function>
//compose(e2,e1) //type mismatch; found   : Int => String required: Boolean => String

//5.2 Lists

def isEmpty[A](l: List[A]) = l match {
  case Nil => true
  case x :: y => false
}

val l1 = List() // same as Nil
val l2 = List(1) // same as 1 :: Nil
val l3 = List(1,2,3) // same as 1 :: 2 :: 3 :: Nil

def length[A](l: List[A]): Int = l match {
  case Nil => 0
  case x :: xs => length(xs) + 1
}

def append[A](l1: List[A], l2: List[A]): List[A] = l1 match {
  case Nil => l2
  case x :: xs => x :: append(xs, l2)
}

//Exercise 11. Define a function map that takes a function f: A => B and a list l:
// List[A] and traverses the list applying f to each element.

def map[A,B](f: A => B, l: List[A]): List[B] = l match{
  case Nil => Nil
  case x::y => f(x) :: map(f,y)
}

// define a function for square
def squareIt(x:Int):Int={x*x}

val l1 = List(1,2,3,4)
println(map[Int,Int](squareIt, l1))

//Exercise 12. Define a function filter that takes a predicate and a list and
// traverses the list, retaining only the elements for which p is true.

def filter[A](p: A => Boolean, l: List[A]): List[A] = l match{
  case Nil => Nil
  case x::y => if (p(x)) {x::filter(p,y)} else{filter(p,y)}
}

def check(x:Int):Boolean = if (x>10){true} else {false}

val l2 = List(10,11,2,3,40)
println(filter[Int](check,l2))

//Exercise 13. Write a function to reverse a list
def reverse[A](l:List[A]):List[A] = l match{
  case Nil => Nil
  case x::y => append[A](reverse[A](y),List(x))
}

println(reverse[Int](l1))

//5.3 Using Scala’s built-in list operations
val l = List(1,2,3,4,5)
l.map(x => x*x)
l.filter(x => x%2 == 0)
l ++ List(7,8,9)

//6 Maps

def empty[K,V]: List[(K,V)] = List()
val map123 = List((1,"a"),(2,"b"), (3,"c"))

//Exercise 14. Define the lookup function:

def lookup[K,V](m: List[(K,V)], k: K): V = m match {
  case Nil => sys.error("No elements in the list")
  case (key,value):: tl => {if (key==k){value} else {lookup[K,V](tl,k)}}
}

println(lookup(map123,3))

//Exercise 15. Define the update function
def update[K,V](m: List[(K,V)], k: K, v: V): List[(K,V)] = m match{
  case Nil => Nil
  case (key,value)::tl => {
    val temp1 = List((key,value))
    val temp2 = List((k,v))
    if (key==k){append(temp2, tl)} else {append(temp1,update[K,V](tl,k,v))}
  }
}

println(update(map123,3,"z")0

//Exercise 16. Define the keys function.
def keys[K,V](m: List[(K,V)]): List[K] = m match {
  case Nil => Nil
  case (k,v):: tl => {
    val temp = List(k)
    append(temp,keys[K,V](tl))
  }
}

println(keys(map123))



//6.1 Using Scala’s built-in ListMaps
import scala.collection.immutable.ListMap

val map12 = ListMap(1 -> "a", 2 -> "b")

println(map12(1))



//Exercise 17. Define the mapping from president numbers to names from Section
// 4.1 as a value

val presidentListMap =  ListMap[String,Int](
  "George H. W. Bush" -> 41,
  "Bill Clinton" -> 42,
  "George W. Bush" -> 43,
  "Barack Obama" -> 44,
  "Donald J. Trump" -> 45)



//Exercise 18. Define map map12 using the empty map and Scala’s update function.
val empty = ListMap[Int,String]()
val map12 = empty + (1 -> "a", 2 -> "b")

//Exercise 19. The Scala ListMap class provides a method toList that converts
// a ListMap[K,V] to a List[(K,V)]. Define a function that converts a
// List[(K,V)] back into a ListMap[K,V].

def list2map[K,V](l: List[(K,V)]): ListMap[K,V] = l match {
  case Nil => ListMap[K,V]()
  case (k,v) :: tail_list => list2map(tail_list)+(k -> v)
}

println(list2map(List((1,"a"),(2,"b"))))


//Exercise 20. The Scala ListMap class provides a method contains, testing
// whether a map m contains a key k which can be written as a method call m.
// contains(k) or infix as m contains k. Using contains, write a
//function election that takes a list of Strings and constructs a
// ListMap[String,Int] such that for each k, the value of m(k) is the
// number of occurrences of k in the initial list.

def election(votes: List[String]): ListMap[String,Int] = votes match{
  case Nil => ListMap[String,Int]()
  case k::tail => { val map_list=election(tail)
    if (map_list.contains(k)){map_list+(k -> (map_list(k)+1))}
    else{map_list+(k -> 1) }
  }}

println(election(List("Hillary","Donald","Hillary")))
