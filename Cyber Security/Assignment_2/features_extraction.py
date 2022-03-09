import subprocess
import re 
import os
import pefile

# function for extrating string tokens from each file
def get_tokens(path):
   text = str(subprocess.check_output(['strings','-n','10',path]))
   text_tokens = text.split(' ')
   
   # preprocess the text and tokenize it
   # took tokens of minimum length=3
   tokens = []
   for t in text_tokens:
      # string to lower case and replace non alpha numeric with space
      t_ = re.sub(r'[\W]',' ',t.lower())
      c = t_.split(' ')
      for c_ in c:
         if len(c_) >=3:
            tokens.append(c_)

   return tokens

# function for extracting the features 
def extract_features(path):
  
  #Parsing PE File using pefile library and extracting static features
  pe = pefile.PE(path)
  features = []
  features.append (pe.FILE_HEADER.Machine)
  features.append (pe.FILE_HEADER.NumberOfSections)
  features.append (pe.FILE_HEADER.NumberOfSymbols)
  features.append (pe.FILE_HEADER.TimeDateStamp)
  features.append (pe.FILE_HEADER.Characteristics)
  features.append (pe.FILE_HEADER.SizeOfOptionalHeader)

  features.append (pe.OPTIONAL_HEADER.Magic)
  features.append (pe.OPTIONAL_HEADER.AddressOfEntryPoint)
  features.append (pe.OPTIONAL_HEADER.CheckSum)
  features.append (pe.OPTIONAL_HEADER.DllCharacteristics)
  features.append (pe.OPTIONAL_HEADER.SectionAlignment)
  features.append (pe.OPTIONAL_HEADER.SizeOfCode)
  features.append (pe.OPTIONAL_HEADER.SizeOfHeaders)
  features.append (pe.OPTIONAL_HEADER.SizeOfHeapCommit)
  features.append (pe.OPTIONAL_HEADER.SizeOfHeapReserve)
  features.append (pe.OPTIONAL_HEADER.SizeOfImage)
  features.append (pe.OPTIONAL_HEADER.SizeOfInitializedData)
  features.append (pe.OPTIONAL_HEADER.SizeOfStackCommit)
  features.append (pe.OPTIONAL_HEADER.SizeOfStackReserve)
  features.append (pe.OPTIONAL_HEADER.SizeOfUninitializedData)
  features.append (pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
  features.append (pe.OPTIONAL_HEADER.LoaderFlags)
  features.append (pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
  features.append (pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
  features.append (pe.OPTIONAL_HEADER.MajorImageVersion)
  features.append (pe.OPTIONAL_HEADER.MinorImageVersion)
  features.append (pe.OPTIONAL_HEADER.MajorLinkerVersion)
  features.append (pe.OPTIONAL_HEADER.MinorLinkerVersion)
  features.append (pe.OPTIONAL_HEADER.MajorSubsystemVersion)
  features.append (pe.OPTIONAL_HEADER.MinorSubsystemVersion)
  features.append (pe.OPTIONAL_HEADER.Reserved1)
  features.append (pe.OPTIONAL_HEADER.Subsystem)

  # check for packed sections present or not 
  sec_names = []
  for section in pe.sections:
    name = section.Name.decode().rstrip('\x00')
    sec_names.append(name)
  
  packed_sec_names = ['.aspack','ASPack','.ASPack','FSG!','.MPRESS1','.MPRESS2',
                       'UPX0','UPX1','UPX2','UPX!','.PX0','.UPX1','.UPX2']
  # finding presence of packed sections 
  packed_sec_count = len(set(sec_names) & set(packed_sec_names))
  if packed_sec_count > 0:
    features.append(1)
  else:
    features.append(0)
  
  try:
    # get number of DLLs
    features.append(len(pe.DIRECTORY_ENTRY_IMPORT))
    #number of import functions 
    imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
    features.append(len(imports))
  except:
    features.append(0)
    features.append(0)
  
  # get word tokens from each file
  # count occuarance of the words features in the file
  # insert count to feature vector corresponding to each important words
  file_tokens = get_tokens(path)

  for token in str_features:
     count = file_tokens.count(token)
     features.append(count)

  return features

#----------------------------------------------------------------------------------
if __name__ =='__main__':
  
  malware_path = 'malware_dataset/malware/'
  benignware_path ='malware_dataset/benignware/'
  
  # Get important string features from malware files
  #-------------------------------------------------
  # get all word tokens from malware files
  malware_tokens = []
  for file_name in os.listdir(malware_path):
     f = malware_path + file_name
     tokens = get_tokens(f)
     malware_tokens.append(tokens)
  
  malware_tokens = sum(malware_tokens, [])
  print('Total number of strings in malware files{}'.format(len(malware_tokens)))
  
   # get all word tokens from all benignmalware files
  benignware_tokens = []
  for file_name in os.listdir(benignware_path):
     f = benignware_path + file_name
     tokens = get_tokens(f)
     benignware_tokens.append(tokens)

  benignware_tokens = sum(benignware_tokens,[])
  print('Total number of strings in benignware files{}'.format(len(benignware_tokens)))
  
  # find unique tokens in malware files which not present in benignware files 
  imp_malware_tokens = list(set(malware_tokens)-set(benignware_tokens)) 
  print('No.  of unique strings in malware files{}'.format(len(imp_malware_tokens))) 
  
  # find 40 best important words from malware files based on count
  # this 40 features act as string features along with PE features
  token_count = []
  for t in imp_malware_tokens:
     count = malware_tokens.count(t)
     token_count.append((t,count))


  sorted_list = sorted(token_count, key = lambda kv:kv[1])
  
  # retrive 40 best features based on frequency of occurance
  str_features = []
  for s,c in sorted_list[-40:]:
     str_features.append(s)
     print(s)




# PE feature names
  PE_features = [
           'Machine',
           'NumberOfSections',
           'NumberOfSymbols',
           'TimeDateStamp',
           'Characteristics',
           'SizeOfOptionalHeader',
           'Magic',
           'AddressOfEntryPoint',
           'CheckSum',
           'DllCharacteristics',
           'SectionAlignment',
           'SizeOfCode',
           'SizeOfHeaders',
           'SizeOfHeapCommit',
           'SizeOfHeapReserve',
           'SizeOfImage',
           'SizeOfInitializedData',
           'SizeOfStackCommit',
           'SizeOfStackReserve',
           'SizeOfUninitializedData',
           'NumberOfRvaAndSizes',
           'LoaderFlags',
           'MajorOperatingSystemVersion',
           'MinorOperatingSystemVersion',
           'MajorImageVersion',
           'MinorImageVersion',
           'MajorLinkerVersion',
           'MinorLinkerVersion',
           'MajorSubsystemVersion',
           'MinorSubsystemVersion',
           'Reserved1',
           'Subsystem',
           'PackedFlag',
           'NumberOfImportedDLLs',
           'NumberOfImportedFunctions']

  print('No. of PE features extracted:{}'.format(len(PE_features)))
  print('No. of string features{}'.format(len(str_features)))

  # all features 
  columns = PE_features+str_features
  columns.append('fileCategory')

  # create a csv file
  file = open('features.csv', 'w')
  file.write(','.join(columns)+'\n')

  
  # Extracting static and string features from all .exe file
  #---------------------------------------------------------
  bad_pe_format = 0
  weired_error = 0

  # parse through beningware files and extract features
  # write feature vectors to the csv file
  for f in os.listdir(benignware_path):
    try:
      features = extract_features(benignware_path+f)
      features.append(0)
      file.write(','.join(map(lambda x:str(x), features))+'\n')
    except pefile.PEFormatError:
      bad_pe_format += 1

  # parse through malware files and extract features
  # write feature vectors to the csv file
  for f in os.listdir(malware_path):
    try:
      features = extract_features(malware_path+f)
      features.append(1)
      file.write(','.join(map(lambda x:str(x), features))+'\n')
    except pefile.PEFormatError:
      bad_pe_format += 1
    except:
      weired_error += 1
  
  # print number of files which are either not PE execuitable orgetting error while parsing
  print(f'No of files rejected: {bad_pe_format+weired_error}')




