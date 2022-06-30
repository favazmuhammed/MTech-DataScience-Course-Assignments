from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment

if __name__ == '__main__':
  
  
  # open the file and get segments inside the elf file
  with open('Hello_ELF','rb') as file:
    elffile = ELFFile(file)                         
    #iterate through each segments
    for segment in elffile.iter_segments():
      # if number of bytes in the file and memory not equal     
      if segment.header.p_filesz != segment.header.p_memsz: 
        # get segment header
        seg_header = segment.header
        
        # print the segment informations
        print("Segments with different sizes in file and memory:\n"+"-"*50)
        print(f"Type: {seg_header.p_type}")
        print(f"Offset: {hex(seg_header.p_offset)}")
        print(f"Virtual address: {hex(seg_header.p_vaddr)}")
        print(f"Physical address: {(seg_header.p_paddr)}")
        print(f"Size in file:{hex(seg_header.p_filesz)}")
        print(f"Size in memory:{hex(seg_header.p_memsz)}")

        # getting sections inside the elffile
        # check which is connected to current segment 
        sections = list()
        for i in range(elffile.num_sections()):
          section = elffile.get_section(i)
          # check section present in current segment
          # if yes append to the sections list
          if segment.section_in_segment(section):
            sections.append(section)

        # print the sections
        if len(sections)<1:
          print("\nNo sections inside the the segment")
        else:
          print(f"\n{len(sections)} sections inside segment:")
          print('-'*26)
          for sec in sections:
            print(f"{sec.name} -- base address: {hex(sec['sh_addr'])}")

    # sections that do not reside in the memory 
    print("\nSections that do not reside in the memory:\n"+'-'*43)
    for section in elffile.iter_sections():
      if section.header.sh_addr == 0:
        print(section.name)
    # close the opened file    
    file.close()