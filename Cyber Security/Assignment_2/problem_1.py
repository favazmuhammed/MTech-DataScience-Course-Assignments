import pefile

#instantiate pefile object for parsing
pe = pefile.PE("/content/data/Hello_PE")

# file can parse with pe file and signature number in hexadecimal 
# start with 50, 45 it is PE execuitable
try:
  # print signature number and Magic number
  print("Signature   : " + hex(pe.NT_HEADERS.Signature))
  print("Magic Number: " + hex(pe.OPTIONAL_HEADER.Magic))

  if (hex(pe.NT_HEADERS.Signature)[2:4] in ['50','45']):
    print('The given file is a PE execuitable')
  else:
    print('The given file is not a PE execuitable')

# files can't parse with pefile is not PE execuitable
except pefile.PEFormatError:
  print('The given file is not a PE execuitable')
      


