import os 
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment


def extract_elf_header_info(path):
  '''function will take path of a binary file and return information /
  from the ELF header as a dictionary with keys as Class, Data, Version, /
  OS/ABI, ABI Version,Type, Machine, Version, Entry point address,/
  Start of program headers, Start of section headers, Flags, Size of this header,/
  Size of program headers, Number of program headers, Size of section headers,/
   Number of section headers, and Section header string table index'''

  # using subprocess get header info
  header_info = str(subprocess.check_output(['readelf','-h',path]))
  
  #split it with '\\n', get necessory info as key value pairs
  contents = header_info.split('\\n')
  information = []
  for line in contents:
    temp = line.strip().split(":")
    information.append(temp)
  
  key_info = {}
  for content in information[1:-1]:
    key_info[content[0].strip()] = content[1].strip()
  return key_info

#-----------------FUNCTION FOR EXTRACTING FEATURES-----------------------------
def extract_features(path):
  '''This function will take path of a binary file and extract /
  features and return it '''
  features = []
   #append file name
  features.append(os.path.basename(path))                 

  # get info from the ELF header and append to features
  key_info = extract_elf_header_info(path)
  features.append(int(key_info['Entry point address'],16))
  features.append(int(key_info['Size of program headers'].split(' ')[0]))
  features.append(int(key_info['Size of section headers'].split(' ')[0]))
  features.append(int(key_info['Start of program headers'].split(' ')[0]))
  features.append(int(key_info['Start of section headers'].split(' ')[0]))

  with open(path,'rb') as file:
    elffile = ELFFile(file)
    
    # get size of data in .text section
    size_text_section = len(elffile.get_section_by_name(".text").data())
    features.append(size_text_section)
    


    total_size_file = 0
    total_size_memory = 0
    n_seg_diff_size_in_file_and_memory = 0
    n_p_type_header_as_int_type = 0
    total_p_flags = 0
    
    for segment in elffile.iter_segments():
      # total size of file and memory
      total_size_file += segment.header.p_filesz
      total_size_memory += segment.header.p_memsz
      # number of segments differ in size of file and memory
      if segment.header.p_filesz != segment.header.p_memsz:
        n_seg_diff_size_in_file_and_memory += 1
      
      # total number of program headers which is integer type
      if type(segment.header.p_type) == int:
        n_p_type_header_as_int_type += 1
      
      # total flags in program headers
      total_p_flags += segment.header.p_flags

    features.append(total_size_file)
    features.append(total_size_memory)
    features.append(n_seg_diff_size_in_file_and_memory)
    features.append(n_p_type_header_as_int_type) 
    features.append(total_p_flags) 
    
    # number of sections not in memory
    n_sec_not_in_memory = 0
    for section in elffile.iter_sections():
      if section.header.sh_addr == 0:
        n_sec_not_in_memory += 1
    features.append(n_sec_not_in_memory)
    
    # retrive information from symbol section
    total_STT_NOTYPE_symbol = 0
    total_STT_FUNC_symbol = 0
    total_STT_OBJECT_symbol = 0
    total_global_symbols = 0
    total_local_symbols = 0
    total_weak_symbols = 0
    try:
      symtab = elffile.get_section_by_name(".dynsym")
      
      for symbol in symtab.iter_symbols():
        # count number of 'STT_NOTYPE','STT_FUNC','STT_OBJECT' symbols
        if symbol.entry.st_info.type =='STT_NOTYPE':
          total_STT_NOTYPE_symbol += total_STT_NOTYPE_symbol
        elif symbol.entry.st_info.type =='STT_FUNC':
          total_STT_FUNC_symbol += total_STT_FUNC_symbol
        elif symbol.entry.st_info.type =='STT_OBJECT':
          total_STT_OBJECT_symbol += total_STT_OBJECT_symbol
        # count number of global, local and weak symbols
        bind = symbol.entry.st_info.bind.split('_')[1]
        if bind == "GLOBAL":
          total_global_symbols += 1
        elif bind == "LOCAL":
          total_local_symbols += 1
        elif bind == "WEAK":
          total_weak_symbols += 1
    except:
      pass
    
    features.append(total_STT_NOTYPE_symbol)
    features.append(total_STT_FUNC_symbol)
    features.append(total_STT_OBJECT_symbol)
    features.append(total_global_symbols)
    features.append(total_local_symbols)
    features.append(total_weak_symbols)

  return features

#-----------MAIN BODY-------------------------------------
if __name__ == "__main__":
  malware_path = "ELF_Dataset/Malware/"
  benignware_path = "ELF_Dataset/Benignware/"
  

  columns = ['name',
             'Entry_point_address',
             'Size_of_program_headers',
             'Size_of_section_headers',
             'Size_of_elf_header',
             'Start_of_program_headers',
             'Start_of_section_headers',
             'size_text_section',
             'total_size_file',
             'total_size_memory',
             'n_seg_diff_size_in_file_and_memory',
             'n_p_type_header_as_int_type',
             'total_p_flags',
             'total_STT_NOTYPE_symbol',
             'total_STT_FUNC_symbol',
             'total_STT_OBJECT_symbol',
             'n_sec_not_in_memory', 
             'total_global_symbols',
             'total_local_symbols',
             'total_weak_symbols', 
             'category'            
  ]

  # create a csv file
  file = open('features.csv', 'w')
  file.write(','.join(columns)+'\n')

  # iterate over all benignware and malware files and retrive features and write to csv file
  for f in os.listdir(benignware_path):
    try:
      features = extract_features(benignware_path+f)
      features.append(0)
      if len(features) == 21:
        file.write(','.join(map(lambda x:str(x), features))+'\n')
    except:
      pass

  for f in os.listdir(malware_path):
    try:
      features = extract_features(malware_path+f)
      features.append(1)
      if len(features)==21:
        file.write(','.join(map(lambda x:str(x), features))+'\n')
    except:
      pass
