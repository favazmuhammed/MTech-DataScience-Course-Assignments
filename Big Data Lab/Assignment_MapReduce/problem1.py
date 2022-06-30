from mrjob.job import MRJob
from mrjob.step import MRStep


class MatrixMultiplication(MRJob):
    def steps(self):
        return [
            MRStep(mapper=self.mapper_1, reducer = self.reducer_1),
            MRStep(mapper=self.mapper_2, reducer = self.reducer_2)
            ]

    # split line and make key value pairs as (column no., (matrix name, row no., value))
    def mapper_1(self, _, line):
        temp = line.split(',')
        (name, row, col, val) = str(temp[0].lstrip('["').rstrip('"')), int(temp[1].lstrip(' ')), int(temp[2].lstrip(' ')), int(temp[3].lstrip(' ').rstrip(']'))
        if name == 'a':
            yield col, (name, row, val)
        elif name == 'b':
            yield row, (name, col, val)


    def reducer_1(self, j, values):
        listA = []
        listB = []
        
        # collect tuples corresponding to each matrix
        for val in values:
            if val[0] == 'a':
                listA.append(val)
            elif val[0] =='b':
                listB.append(val)

        # for each value (a,i,aij) for a, and each value, (b,k,bjk) from b, 
        # produce a key-value pair with key equal to (i,k) and 
        # value equal to the product of these elements, aij*bjk.
        for (A, i, valA) in listA:
            for (B, k, valB) in listB:
                yield (i,k), valA*valB
    
  
    def mapper_2(self, key, value):
        yield key, value
    
    # for each key (i,k), produce the sum of the list of values associated with this key
    def reducer_2(self, key, values):
        yield key, sum(values)

if __name__ == '__main__':
    MatrixMultiplication.run()