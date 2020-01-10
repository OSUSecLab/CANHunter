# This is a backward slicing analysis program for native libs

from Common import *
from idautils import *
from idaapi import *
from idc import *
import os
import re


# read call graph to memory as a dict {key: value}
# key: function     value: caller  (value ->(call) key)
def read_call_graph():
    res = {}
    with open("./graph/" + get_root_filename(), 'r') as i:
        for line in i.readlines():
            tokens = line[:-1].replace('\t', '').split('->')
            if tokens[0] == "" or tokens[1] == "":
                continue
            else:
                if tokens[1] not in res.keys():
                    res[tokens[1]] = []
                res[tokens[1]].append(tokens[0])

    return res


# get references of the api from the call graph
def get_ref_from_call_graph(api, graph):
    if api not in graph.keys():
        return []
    callers = graph[api]
    return callers


# trace back and find the ui
def ui_trace(address, exist):
    keywords = ["pressed", "tapped", "clicked", 'button', 'viewdidload']
    name = GetFunctionName(address)
    new_exist = list(exist)
    new_exist.append(name)
    for keyword in keywords:
        if name.lower().__contains__(keyword):
            return name

    global graph
    refs = get_ref_from_call_graph(name, graph)
    func = ""
    for ref in refs:
        if name != ref:
            if ref not in exist:
                func = ui_trace(get_name_ea(0, ref), new_exist)
                if func != "":
                    return func

    return func


def get_call_graph(apis):
    output_dir = "/Users/onehouwong/Desktop/CANHunter Usenix Sec 19'/vehicle_crawler/Executor/graph/"

    with open(os.path.join(output_dir, get_root_filename()), 'w') as w:
        w.write("")  # clear file

    out = open(os.path.join(output_dir, get_root_filename()), "a")

    # build call graph with starting apis
    # find all callers from the root, i.e., the api
    for api in apis:
        if api.__contains__("["):
            selector = api.split(' ')[-1][:-1]
            ref = get_name_ea(0, function_name_parser(selector))

            for x in find_xref(ref):
                print GetFunctionName(x) + "\t->\t" + api
                print >> out, GetFunctionName(x) + "\t->\t" + api
                build_call_graph(x, out, True)
        else:
            ref = get_name_ea(0, api)
            build_call_graph(ref, out, True)

    # build whole call graph
    if apis == []:
        out = open(os.path.join(output_dir, get_root_filename()), "a")
        ea = BeginEA()
        for funcea in Functions(SegStart(ea), SegEnd(ea)):
            build_call_graph(funcea, out, False)


# backward build the call graph
def build_call_graph(address, out, recursive):
    global stack
    if not GetFunctionName(address).__contains__("["):
        # sub function
        xrefs = get_ref_func(address)
        for xref in xrefs.values():
            if GetDisasm(xref).__contains__('DCQ'):
                cnt = 0
                v_table_address = xref
                # deal with C++ virtual function invocation
                while True:
                    if GetDisasm(v_table_address).__contains__('DCQ 0'):
                        break
                    v_table_address -= 8
                    cnt += 1

                    if cnt > 200:
                        # should not loop too much...
                        return

                print "vtable address = " + hex(v_table_address)

                for xref in find_xref(v_table_address):
                    if GetFunctionName(xref) + "\t->\t" + GetFunctionName(address) not in stack:
                        print GetFunctionName(xref) + "\t->\t" + GetFunctionName(address)
                        print >> out, GetFunctionName(xref) + "\t->\t" + GetFunctionName(address)
                        stack.append(GetFunctionName(xref) + "\t->\t" + GetFunctionName(address))
                        if recursive:
                            build_call_graph(xref, out, recursive)

            else:
                print GetFunctionName(xref) + "\t->\t" + GetFunctionName(address)
                print >> out, GetFunctionName(xref) + "\t->\t" + GetFunctionName(address)
                if GetFunctionName(xref) + "\t->\t" + GetFunctionName(address) not in stack:
                    stack.append(GetFunctionName(xref) + "\t->\t" + GetFunctionName(address))
                    if recursive:
                        build_call_graph(xref, out, recursive)

        if xrefs.values().__len__() == 0:
            # dead code
            return

    elif GetFunctionName(address).__contains__("["):
        xrefs = get_ref_func(address)
        for xref in xrefs.values():
            print GetFunctionName(xref) + "\t->\t" + GetFunctionName(address)
            print >> out, GetFunctionName(xref) + "\t->\t" + GetFunctionName(address)
            if GetFunctionName(xref) + "\t->\t" + GetFunctionName(address) not in stack:
                stack.append(GetFunctionName(xref) + "\t->\t" + GetFunctionName(address))
                if recursive:
                    build_call_graph(xref, out, recursive)

#
# if __name__ == '__main__':
#     global graph
#     graph = read_call_graph()
#     # apis = ["-[CBPeripheral writeValue:forCharacteristic:type:]",
#     #         "-[NSOutputStream write:maxLength:]"]
#     get_call_graph([])
