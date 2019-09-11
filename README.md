## 功能：
一键解析android elf到json（LIEF库调用示例）  

## 运行环境：
win10 x64 1903  
ida 7.0

## Example：  
#### >>>  lief_az_elf.exe libsm4.so libsm4.json  

## 注释：  

```python
# 初始化
 bin = lief.parse(input__)
 
 # head
tmp = {}
tmp["arm_flags_list"] = str(bin.header.arm_flags_list)
tmp["entrypoint"] = str(bin.header.entrypoint)
tmp["file_type"] = str(bin.header.file_type)
tmp["header_size"] = str(bin.header.header_size)
tmp["hexagon_flags_list"] = str(bin.header.hexagon_flags_list)
tmp["identity"] = str(bin.header.identity)
tmp["identity_class"] = str(bin.header.identity_class)
tmp["identity_data"] = str(bin.header.identity_data)
tmp["identity_os_abi"] = str(bin.header.identity_os_abi)
tmp["identity_version"] = str(bin.header.identity_version)
tmp["machine_type"] = str(bin.header.machine_type)
tmp["mips_flags_list"] = str(bin.header.mips_flags_list)
tmp["numberof_sections"] = str(bin.header.numberof_sections)
tmp["numberof_segments"] = str(bin.header.numberof_segments)
tmp["object_file_version"] = str(bin.header.object_file_version)
tmp["ppc64_flags_list"] = str(bin.header.ppc64_flags_list)
tmp["processor_flag"] = str(bin.header.processor_flag)
tmp["program_header_offset"] = str(bin.header.program_header_offset)
tmp["program_header_size"] = str(bin.header.program_header_size)
tmp["section_header_offset"] = str(bin.header.section_header_offset)
tmp["section_header_size"] = str(bin.header.section_header_size)
tmp["section_name_table_idx"] = str(bin.header.section_name_table_idx)

# sections
for k in bin.sections:
    tmp = {}
    tmp["alignment"] = str(k.alignment)
    # tmp["content"] = str(k.content)
    # tmp["entropy"] = str(k.entropy)
    tmp["entry_size"] = str(k.entry_size)
    tmp["file_offset"] = str(k.file_offset)
    tmp["flags"] = str(k.flags)
    tmp["flags_list"] = str(k.flags_list)
    tmp["information"] = str(k.information)
    tmp["link"] = str(k.link)
    tmp["name"] = str(k.name)
    tmp["name_idx"] = str(k.name_idx)
    tmp["offset"] = str(k.offset)
    tmp["original_size"] = str(k.original_size)
    # tmp["segments"] = str(k.segments)
    tmp["size"] = str(k.size)
    tmp["type"] = str(k.type)
    tmp["virtual_address"] = str(k.virtual_address)
  
  
# segments
for k in bin.segments:
    tmp = {}
    tmp["alignment"] = str(k.alignment)
    # tmp["content"] = str(k.content)
    tmp["file_offset"] = str(k.file_offset)
    tmp["physical_address"] = str(k.physical_address)
    tmp["physical_size"] = str(k.physical_size)
    # tmp["sections"] = str(k.sections)
    tmp["type"] = str(k.type)
    tmp["virtual_address"] = str(k.virtual_address)
    tmp["virtual_size"] = str(k.virtual_size)

# relocations
for k in bin.relocations:
    tmp = {}
    tmp["addend"] = str(k.addend)
    tmp["address"] = str(k.address)
    tmp["has_section"] = str(k.has_section)
    tmp["has_symbol"] = str(k.has_symbol)
    tmp["info"] = str(k.info)
    tmp["is_rel"] = str(k.is_rel)
    tmp["is_rela"] = str(k.is_rela)
    tmp["purpose"] = str(k.purpose)
    tmp["size"] = str(k.size)
    tmp["type"] = str(k.type)
    try:
        tmp["symbol.name"] = str(k.symbol.name)
        tmp["symbol.is_function"] = str(k.symbol.is_function)
        tmp["symbol.is_variable"] = str(k.symbol.is_variable)
        tmp["symbol.information"] = str(k.symbol.information)
    except:
        tmp["symbol.name"] = "None"
        tmp["symbol.is_function"] = "None"
        tmp["symbol.is_variable"] = "None"
        tmp["symbol.information"] = "None"
        l.append(tmp)
        continue
        
# dynamic_symbols
for k in bin.dynamic_symbols:
    tmp = {}
    tmp["binding"] = str(k.binding)
    tmp["exported"] = str(k.exported)
    tmp["has_version"] = str(k.has_version)
    tmp["imported"] = str(k.imported)
    tmp["information"] = str(k.information)
    tmp["is_function"] = str(k.is_function)
    tmp["is_static"] = str(k.is_static)
    tmp["is_variable"] = str(k.is_variable)
    tmp["name"] = str(k.name)
    tmp["other"] = str(k.other)
    tmp["shndx"] = str(k.shndx)
    tmp["size"] = str(k.size)
    tmp["type"] = str(k.type)
    tmp["value"] = str(k.value)
    tmp["visibility"] = str(k.visibility)

```
