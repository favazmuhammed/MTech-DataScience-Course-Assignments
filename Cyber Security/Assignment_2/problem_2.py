import pefile

#instantiating pefile object for parsing the file
pe = pefile.PE("Hello_PE")


#first 10 bytes in the .rsrc section
for section in pe.sections:
  if section.Name.decode().rstrip('\x00') == '.rsrc':
    for b in section.get_data()[:10]:
      print(b)

# value in AddressOfEntryPoint field
print("AddressOfEntryPoint: " + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))