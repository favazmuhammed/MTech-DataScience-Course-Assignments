
import re
import sys

def change_date_format(text):
  
  # category of months having 30 days and 31 days
  group_31 = ['January','March','May','July','August','October','December']
  group_30 = ['April','June','September','November']

  # dictionary with value as each month's name matching regular expressions corresponding to each month
  # matching strings replace with key value
  expressions = {'January':'(01|[Jj][Aa][Nn](?:[Uu][Aa][Rr][Yy])?)',
                 'February':'(02|[Ff][Ee][Bb](?:[Rr][Uu][Aa][Rr][Yy])?)',
                 'March':'(03|[Mm][Aa][Rr](?:[Cc][Hh])?)',
                 'April':'(04|[Aa][Pp][Rr](?:[Ii][Ll])?)',
                 'May':'(05|[Mm][Aa][Yy])',
                 'June':'(06|[Jj][Uu][Nn](?:[Ee])?)',
                 'July':'(07|[Jj][Uu][Ll](?:[Yy])?)',
                 'August':'(08|[Aa][Uu][Gg](?:[Uu][Ss][Tt])?)',
                 'September':'(09|[Ss][Ee][Pp](?:[Tt][Ee][Mm][Bb][Ee][Rr])?)',
                 'October':'(10|[Oo][Cc][Tt](?:[Oo][Bb][Ee][Rr])?)',
                 'November':'(11|[Nn][Oo][Vv](?:[Ee][Mm][Bb][Ee][Rr])?)',
                 'December':'(12|[Dd][Ee][Cc](?:[Ee][Mm][Bb][Ee][Rr])?)'
                 }

  # iterate over each month and corresponding month's name matching expressions 
  for month, exp in expressions.items():
    if month in group_31:
      # compleate regular expression which matches strings like 25 jan 2022, 23/12/2000 etc
      match_exp1 = '((0[1-9]|[12][0-9]|3[01])(?:th|rd)?[-, /.]+)'+exp+'([-, /.]+(\d{4}))'
      # compleate regular expression which matches strings like 25 jan, 23rd december etc
      match_exp2 = '((0[1-9]|[12][0-9]|3[01])(?:th|rd)?[-, /.]+)'+exp+'(?![\w]*[-, /.]+(\d{4}))'
      # compleate regular expression which matches strings January, 14 2020 etc
      match_exp3 = exp+'([-, /.]+(0[1-9]|[12][0-9]|3[01])(?:th|rd)?[-, /.]+)(\d{4})'
      # compleate regular expression which matches strings January, 14th etc
      match_exp4 = exp+'([-, /.]+(0[1-9]|[12][0-9]|3[01])(?:th|rd)?)[ ]+'
    
    # same procedure as above but no 31st day
    elif month in group_30:
      match_exp1 = '((0[1-9]|[12][0-9]|30)(?:th|rd)?[-, /.]+)'+exp+'([-, /.]+(\d{4}))'
      match_exp2 = '((0[1-9]|[12][0-9]|30)(?:th|rd)?[-, /.]+)'+exp+'(?![\w]*[-, /.]+(\d{4}))'
      match_exp3 = exp+'([-, /.]+(0[1-9]|[12][0-9]|30)(?:th|rd)?[-, /.]+)(\d{4})'
      match_exp4 = exp+'([-, /.]+(0[1-9]|[12][0-9]|30)(?:th|rd)?)[ ]+'
    
    # for February same expressions but days upto 29
    elif month == 'February':
      match_exp1 = '((0[1-9]|[12][0-9])(?:th|rd)?[-, /.]+)'+exp+'([-, /.]+(\d{4}))'
      match_exp2 = '((0[1-9]|[12][0-9])(?:th|rd)?[-, /.]+)'+exp+'(?![\w]*[-, /.]+(\d{4}))'
      match_exp3 = exp+'([-, /.]+(0[1-9]|[12][0-9])(?:th|rd)?[-, /.]+)(\d{4})'
      match_exp4 = exp+'([-, /.]+(0[1-9]|[12][0-9])(?:th|rd)?)[ ]+'

    # replace strings 
    replace_exp1 ='<date std_date="\\2-'+month+'-\\5">\\1\\3\\4</date>'
    replace_exp2 ='<date std_date="\\2-'+month+'-2022">\\1\\3</date> '
    replace_exp3 ='<date std_date="\\3-'+month+'-\\4">\\1\\2\\4</date>'
    replace_exp4 ='<date std_date="\\3-'+month+'-2022">\\1\\2</date> '
    
    # substituting matched strings replace strings
    text = re.sub(match_exp1,replace_exp1,text)
    text = re.sub(match_exp2,replace_exp2,text)
    text = re.sub(match_exp3,replace_exp3,text)
    text = re.sub(match_exp4,replace_exp4,text)

  return text

if __name__ == "__main__":
  inFile = sys.argv[1]
  outFile = sys.argv[2]

  with open(inFile,'r',encoding='utf-8') as i:
    lines = i.readlines()

  input_text = ""
  for line in lines:
    input_text += line
  processed_text = change_date_format(input_text)
  
  with open(outFile,'w') as o:
    o.write('<output>'+processed_text+'</output>')
