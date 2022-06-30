from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment

if __name__ == '__main__':

  # open the file and get segments inside the elf file
  with open('Hello_ELF','rb') as file:
    elffile = ELFFile(file)
    # get content in '.text' section     
    text_section = elffile.get_section_by_name(".text")
    print("First 10 bytes in '.text' section:\n"+'-'*35)
    # print 10 bytes 
    print(text_section.data()[:10])
    
    # get contents in the '.dynsym' section
    symtab = elffile.get_section_by_name(".dynsym")
    # initializing counts
    globalCount = 0
    localCount = 0
    weakCount = 0

    # iterate through each symbols 
    for symbol in symtab.iter_symbols():
      # if type of thw symbol is STT_FUNC
      if symbol.entry.st_info.type == "STT_FUNC":

        # count global, local and weak
        bind = symbol.entry.st_info.bind.split('_')[1]
        if bind == "GLOBAL":
          globalCount += 1
        elif bind == "LOCAL":
          localCount += 1
        elif bind == "WEAK":
          weakCount += 1
    # print the results
    print("\nCount of symbols in '.dynsym' section\n"+'-'*37)
    print(f"Global    : {globalCount}")
    print(f"Local     : {localCount}")
    print(f"Weak      : {weakCount}")