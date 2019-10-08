import os
import lief, json, sys

# 读取参数(A)
def get_param_a():
    try:
        num = len(sys.argv)
        if (3 != num):
            print("get_param(),fail.")
            raise BaseException
        input = sys.argv[1]
        output = sys.argv[2]
        return input, output
    except:
        raise BaseException

# 读取参数(B)
def get_param_b():
    try:
        num = len(sys.argv)
        if (2 != num):
            print("get_param(),fail.")
            raise BaseException
        param = sys.argv[1]
        root = os.path.dirname(param)
        name = os.path.splitext(os.path.basename(param))[0]
        output_file_path = root + "\\" + "lief__" + name + ".json"
        return param, output_file_path
    except:
        raise BaseException

# 分析过程
def az_elf(input__):
        try:
            bin = lief.parse(input__)
            content = {}

            # 1 保存elfhead
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

            content["header"] = tmp

            # 2 保存dynamic_entries
            l = []
            for k in bin.dynamic_entries:
                tmp = {}
                tmp["tag"] = str(k.tag)
                tmp["value"] = str(k.value)
                if (True == hasattr(k, "name")):
                    tmp["name"] = str(getattr(k, "name"))
                else:
                    tmp["name"] = "None"
                if (True == hasattr(k, "array")):
                    tmp["array"] = str(getattr(k, "array"))
                else:
                    tmp["array"] = "None"
                l.append(tmp)

            # loop(bin.dynamic_entries)
            content["dynamic_entries"] = l

            # 3 保存sections
            d = {}
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
                d[tmp["name"]] = tmp
            content["sections"] = d

            # 4 保存segments
            l = []
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
                l.append(tmp)

            content["segments"] = l

            # 5 保存relocations
            l = []
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
                l.append(tmp)

            content["relocations"] = l

            # 6 保存dynamic_relocations
            l = []
            for k in bin.dynamic_relocations:
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
                l.append(tmp)

            content["dynamic_relocations"] = l

            # 7 保存pltgot_relocations
            l = []
            for k in bin.pltgot_relocations:
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
                l.append(tmp)

            content["pltgot_relocations"] = l

            # 8 保存dynamic_symbols
            l = []
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
                try:
                    tmp["symbol_version"] = str(k.symbol_version)
                except:
                    tmp["symbol_version"] = "None"
                    l.append(tmp)
                    continue
                l.append(tmp)

            content["dynamic_symbols"] = l

            # 9 保存exported_symbols
            l = []
            for k in bin.exported_symbols:
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
                try:
                    tmp["symbol_version"] = str(k.symbol_version)
                except:
                    tmp["symbol_version"] = "None"
                    l.append(tmp)
                    continue
                l.append(tmp)

            content["exported_symbols"] = l

            # 10 保存imported_symbols
            l = []
            for k in bin.imported_symbols:
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
                try:
                    tmp["symbol_version"] = str(k.symbol_version)
                except:
                    tmp["symbol_version"] = "None"
                    l.append(tmp)
                    continue
                l.append(tmp)

            content["imported_symbols"] = l

            # 11 保存exported_functions
            l = []
            for k in bin.exported_functions:
                l.append(str(k))
                pass

            content["exported_functions"] = l

            # 12 保存imported_functions
            l = []
            for k in bin.imported_functions:
                l.append(str(k))
                pass

            content["imported_functions"] = l

            # 13 保存sysv_hash
            tmp = {}
            tmp["use_sysv_hash"] = str(bin.use_sysv_hash)
            if (True == bin.use_sysv_hash):
                tmp["sysv_hash.nbucket"] = str(bin.sysv_hash.nbucket)
                tmp["sysv_hash.nchain"] = str(bin.sysv_hash.nchain)
                tmp["sysv_hash.buckets"] = str(bin.sysv_hash.buckets)
                tmp["sysv_hash.chains"] = str(bin.sysv_hash.chains)
            else:
                tmp["sysv_hash.nbucket"] = "None"
                tmp["sysv_hash.nchain"] = "None"
                tmp["sysv_hash.buckets"] = "None"
                tmp["sysv_hash.chains"] = "None"

            content["sysv_hash"] = tmp

            # 14 保存gnu_hash
            tmp = {}
            tmp["use_gnu_hash"] = str(bin.use_gnu_hash)
            if (True == bin.use_gnu_hash):
                tmp["gnu_hash.bloom_filters"] = str(bin.gnu_hash.bloom_filters)
                tmp["gnu_hash.buckets"] = str(bin.gnu_hash.buckets)
                tmp["gnu_hash.hash_values"] = str(bin.gnu_hash.hash_values)
                tmp["gnu_hash.nb_buckets"] = str(bin.gnu_hash.nb_buckets)
                tmp["gnu_hash.shift2"] = str(bin.gnu_hash.shift2)
                tmp["gnu_hash.symbol_index"] = str(bin.gnu_hash.symbol_index)
            else:
                tmp["gnu_hash.bloom_filters"] =  "None"
                tmp["gnu_hash.buckets"] =  "None"
                tmp["gnu_hash.hash_values"] =  "None"
                tmp["gnu_hash.nb_buckets"] =  "None"
                tmp["gnu_hash.shift2"] =  "None"
                tmp["gnu_hash.symbol_index"] =  "None"

            content["gnu_hash"] = tmp

            # 15 保存剩下的
            tmp = {}
            tmp["name"] = str(bin.name)
            tmp["virtual_size"] = str(bin.virtual_size)
            tmp["is_pie"] = str(bin.is_pie)
            tmp["libraries"] = ','.join(bin.libraries)
            tmp["has_interpreter"] = str(bin.has_interpreter)
            tmp["has_notes"] = str(bin.has_notes)
            tmp["has_nx"] = str(bin.has_nx)
            if (True == bin.has_interpreter):
                tmp["interpreter"] = str(bin.interpreter)
            else:
                tmp["interpreter"] = "None"

            content["stuff"] = tmp

            # 返回
            return content
        except:
            print("fail.")
            raise BaseException
        pass

# 保存
def save(output__, content):
    with open(output__, 'w+') as f:
        json.dump(fp=f, obj=content)
    return

# 命令行参数
# 1 输入路径 SO
# 2 输出路径 JSON
if ("__main__" == __name__):
    try:
        input, output = get_param_a()  # 命令行参数：1 输入路径SO；2 输出路径JSON
        #input, output = get_param_b() # 命令行参数：1 输入路径
        content = az_elf(input)
        save(output, content)
        print("success.")
    except:
        print("fail.")
    pass


##################################################
# 打印对象
# def loop(obj):
#     for k in obj:
#         print(k)
#     return

# 以下代码仅用于查看熟悉LIEF对象成员
# def get_number_list1(obj):
#     l = []
#     for a in dir(obj):
#         try:
#             s = str(a)
#             getattr(obj, s)
#             if(-1==s.find("__")):
#                 l.append(s)
#         except:
#             continue
#     return l
#
# def get_number_list2(obj):
#     l = []
#     ele = None
#     for ele in obj:
#         break
#     for a in dir(ele):
#         try:
#             s = str(a)
#             getattr(ele, s)
#             if(-1==s.find("__")):
#                 l.append(s)
#         except:
#             continue
#     return l
# l1 = get_number_list1(bin.header)
# l2 = get_number_list2(bin.dynamic_entries)
# l3 = get_number_list2(bin.sections)
# l4 = get_number_list2(bin.segments)
# l5 = get_number_list2(bin.relocations)
# l6 = get_number_list2(bin.dynamic_relocations)
# l7 = get_number_list2(bin.pltgot_relocations)
# l8 = get_number_list2(bin.dynamic_symbols)
# l9 = get_number_list2(bin.exported_symbols)
# l10 = get_number_list2(bin.imported_symbols)
# l11=get_number_list1(bin.sysv_hash)
# print(bin.libraries)
# print(bin)
##################################################