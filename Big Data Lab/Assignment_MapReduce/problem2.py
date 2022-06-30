from mrjob.job import MRJob
from mrjob.step import MRStep

no_columnsB = 5
no_rowsA = 5
no_columnsA = no_rowsB = 5

class MatrixMultiplication(MRJob):
  
    def steps(self):
        return [
            MRStep(mapper=self.mapper, reducer = self.reducer)
            ]

    def mapper(self, _, line):
        matrixA = []
        matrixB = []
        
        # spli the line with comma and get matrix name, column no. , row no. and value
        temp = line.split(',')
        (name, row, col, val) = str(temp[0].lstrip('["').rstrip('"')), int(temp[1].lstrip(' ')), int(temp[2].lstrip(' ')), int(temp[3].lstrip(' ').rstrip(']'))
        
        # produce (key, value) pairs as ((i,k),(a,j,aij)) for k = 0,1,  number of column of b
        if name == 'a':
            matrixA.append((row, col, val))
            for k in range(no_columnsB):
                yield (row, k), ('a', col, val)

        # produce (key, value) pairs as ((i,k),(b,j,bjk)) for i = 0,1,  number of rows of a
        if name == 'b':
            matrixB.append((row, col, val))
            for i in range(no_rowsA):
                yield (i, col), ('b', row, val)

  
    def reducer(self, key, values):
        listA = []
        listB = []
        prodList = []
        
        # collect tuples of each matrix
        for val in values:
            if val[0] == 'a':
                listA.append(val)
            elif val[0] == 'b':
                listB.append(val)

        # multiply elements corresponding to same j from both matrix
        for (A, j1, valA) in listA:
            for (B, j2, valB) in listB:
                if j1 == j2:
                    prodList.append(valA*valB)

        yield key, sum(prodList)


if __name__ == '__main__':
    MatrixMultiplication.run()