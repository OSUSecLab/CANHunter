from idautils import *
from idaapi import *
from idc import *
from Common import *
from Strings import models
import re
import time
import json
import os

PATTERN_VARIABLE = re.compile(r'\b[va]\d+\b|\bself\b')
project_path = ""
output_json = {}
index = 0

exist = []

semantic_time = 0
branch_count = 0
instruction_count = 0


class VarNode:
    def __init__(self, name, func, index, t):
        self.name = name
        self.next = []
        self.function_call = func
        self.index = index
        self.calls = []
        self.targets = t

    # function name, in complete format
    def get_name(self):
        return self.name

    def set_next(self, node):
        self.next.append(node)

    # next node
    def get_next(self, index=-999):
        if index == -999:
            return self.next
        else:
            return self.next[index]

    # target list
    def get_target(self):
        return self.targets

    def add_calls(self, call):
        if call not in self.calls:
            self.calls.append(call)

    # function calls in the current function
    def get_calls(self):
        return self.calls

    def set_function_call(self, name):
        self.function_call = name

    def get_function_call(self):
        return self.function_call

    def get_index(self):
        return self.index

    def __str__(self):
        if self.name == "root":
            return "root"
        out = ""
        for call in self.calls:
            out += call
            if self.calls.index(call) != self.calls.__len__()-1:
                out += "\n"
        return out


def start_tracing(fun, index):

    start = time.time()

    api = function_name_truncate(fun)

    xrefs = find_xref(get_name_ea(0, function_name_parser(api)))

    root = VarNode(name="root", func="", index=0, t=[])

    for xref in xrefs:
        code = get_pesudocode(xref)
        if code is None:
            continue
        code = code.split("\n")

        line_index = found_target_function(code, api)
        if line_index == -1:
            continue
        # print line_index
        functioncall = get_complete_function_call(code, line_index)
        # print functioncall
        arguments = extract_all_arguments(functioncall)
        # print arguments

        target = [arguments[index]]
        node = VarNode(GetFunctionName(xref), functioncall, line_index, target)
        root.set_next(node)
        recursive_trace(node, [])

        # clear file

    # with open("./log/%s.txt" % get_root_filename(),
    #           "w") as o:
    #     print >> o, "",

    global project_path
    global output_json
    path_file = os.path.join(project_path, "BackwardSlicing", "path", "%s.json" % get_root_filename())

    print_all_paths(root, [])

    with open(path_file, "w") as o:
        json.dump(output_json, o)  # clear file before print path

    finish_time = time.time() - start
    print "Finish ! time = %f " % finish_time
    print "Semantic recovery time = %f" % semantic_time
    print "Tracing time = %f" % (finish_time - semantic_time)
    print "Total branch = %d" % branch_count
    print "Total instruction = %d" % instruction_count


def print_all_paths(node, path):
    if node is None:
        return
    path.append(node.__str__())

    if node.get_next().__len__() == 0:
        # leave node
        # continue to trace and find semantic: function and car model
        semantic_start = time.time()
        flist, tlist = func_call_trace(node.get_name(), [])

        car = find_brand(tlist+flist+path)
        ui = find_ui(tlist)
        semantic_end = time.time()

        global semantic_time, branch_count, instruction_count, output_json, project_path, index
        semantic_time += semantic_end - semantic_start

        # output execution path to json
        out = dict()
        out['path'] = []
        for p in path:
            if p != "root":
                for ps in p.split("\n"):
                    out['path'].append(ps)
        instruction_count += path.__len__()
        branch_count += 1

        out['model'] = car
        out['ui'] = ui
        # print >> o, "CarBrand: ",
        # print >> o, car
        # print >> o, "UI: ",
        # print >> o, ui
        # print >> o
        # json.dump(json.dumps(out, indent=4), o)
        output_json[index] = out
        index += 1
    else:
        for child in node.get_next():
            print_all_paths(child, list(path))


# Trace from leave node to the top functions
# tlist: functions at top level
# flist: other functions along the path
def func_call_trace(func, exist):
    exist.append(function_name_truncate(func))
    refs = get_ref_func(get_name_ea(0, func))
    if refs.__len__() != 0:
        temp_flist = [func]
        temp_tlist = []
        for ref in refs.keys():
            if function_name_truncate(ref) not in exist:  # prevent infinite recurrence
                f, t = func_call_trace(ref, exist)
                temp_flist += f
                temp_tlist += t
        return temp_flist, temp_tlist
    else:
        # functions on the top
        return [], [func]


def find_ui(path):
    keyword = ["pressed", "tapped", 'clicked', 'button', 'viewdidload', 'viewcontroller']
    map = get_button_text_mapping()
    for func in path:
        # find UI semantics
        if function_name_truncate(func) in map.keys():
            return map[function_name_truncate(func)]

        for key in keyword:
            if key in func.lower():
                # return func.split(" ")[0][2:]
                return func
    return None


# determine if the executing path indicates car brand
def find_brand(path):
    for func in path:
        for model in models:
            if model in func:
                return model
    return None


def recursive_trace(node, exist):
    # within a function
    code = get_pesudocode(get_name_ea(0, node.get_name())).split('\n')
    if code is None:
        return
    _range = range(0, node.get_index())
    _range.reverse()
    var_set = node.get_target()
    for i in _range:

        if code[i].__contains__("=") and not code[i].__contains__(">=") and not code[i].__contains__("<="):
            if code[i].split("=")[0].strip() in var_set:
                # left argument, the target
                target = code[i].split("=")[0].strip()
                call = get_complete_function_call(code, i)

                arguments = extract_all_arguments(call)
                if call.__contains__("objc_retainAutoreleasedReturnValue") or call.__contains__(
                            "objc_retainAutorelease"):
                    # deal with objc_retainAutoreleasedReturnValue
                    call = target + " = " + arguments[0]
                elif call.__contains__("objc_retain"):
                    # deal with objc_retain
                    if arguments.__len__() >= 2:
                        if arguments[1] == "a2":
                            call = target + " = " + arguments[0]
                        else:
                            call = target + " = " + arguments[1]
                else:
                    if call.__contains__("objc_msgSend") or call.__contains__("-[") or call.__contains__("+["):
                        call = target + " = objc_msgSend("
                        for arg in arguments:
                            call += arg + ', '
                        call = call[:-2]  # eliminate the last ","
                        call += ");"
                    else:
                        # assignment operation
                        pass

                node.add_calls(call)

                # add argument in the set
                for arg in arguments:
                    if arg == "a2":
                        continue
                    if PATTERN_VARIABLE.findall(arg).__len__() != 0:
                        for v in PATTERN_VARIABLE.findall(arg):
                            if v not in var_set:
                                var_set.append(v)

    print node.get_name()
    print var_set
    for c in node.get_calls():
        print c
    print

    targets = []
    for v in var_set:
        if v.__contains__('a'):
            try:
                targets.append(int(v.replace("a", "")))
            except Exception:
                continue

    # switch function
    if targets.__len__() != 0:
        # first, set up the target parameter in the next function
        add = get_name_ea(0, node.get_name())
        refs_dict = get_ref_func(add)
        for f in refs_dict.keys():
            c = get_pesudocode(refs_dict[f])
            if c is None:
                continue
            code = c.split('\n')
            line_index = found_target_function(code, function_name_truncate(node.get_name()))
            if line_index == -1:
                # function call not found...
                continue
            functioncall = get_complete_function_call(code, line_index)
            arguments = extract_all_arguments(functioncall)
            tar = []

            print node.get_name() + " >> " + f
            print functioncall
            print arguments
            print targets
            try:
                for _t in targets:
                    tar.append(arguments[_t-1])
            except Exception:
                continue

            if f not in exist:
                # add conjunction calls
                new = VarNode(name=f, func=functioncall, index=line_index, t=tar)
                for _t in targets:
                    new.add_calls("%s = %s" % ("a" + str(_t), arguments[_t - 1]))
                # new.add_calls(functioncall)
                node.set_next(new)
                new_exist = list(exist)
                new_exist.append(f)
                recursive_trace(new, new_exist)


def get_button_text_mapping():
    api = "addTarget:action:forControlEvents:"

    # create a map to record UI function and its title string
    # methodName : titleString
    map = {}

    xrefs = find_xref(get_name_ea(0, function_name_parser(api)))
    for xref in xrefs:
        print GetFunctionName(xref)

        code = get_pesudocode(xref)
        if code is None:
            continue
        code = code.split("\n")

        line_index = found_target_function(code, api)
        if line_index == -1:
            continue

        functioncall = get_complete_function_call(code, line_index)
        arguments = extract_all_arguments(functioncall)
        current_method = arguments[3]  # button onclick method
        print current_method

        _range = range(0, line_index)
        _range.reverse()
        var_set = [arguments[2]]
        for i in _range:

            if code[i].__contains__("=") and not code[i].__contains__(">=") and not code[i].__contains__("<="):
                if code[i].split("=")[0].strip() in var_set:
                    # left argument, the target
                    target = code[i].split("=")[0].strip()
                    call = get_complete_function_call(code, i)

                    arguments = extract_all_arguments(call)
                    if call.__contains__("objc_retainAutoreleasedReturnValue") or call.__contains__(
                            "objc_retainAutorelease"):
                        # deal with objc_retainAutoreleasedReturnValue
                        call = target + " = " + arguments[0]
                    elif call.__contains__("objc_retain"):
                        # deal with objc_retain
                        if arguments.__len__() >= 2:
                            if arguments[1] == "a2":
                                call = target + " = " + arguments[0]
                            else:
                                call = target + " = " + arguments[1]
                    else:
                        if call.__contains__("objc_msgSend") or call.__contains__("-[") or call.__contains__("+["):
                            call = target + " = objc_msgSend("
                            for arg in arguments:
                                call += arg + ', '
                            call = call[:-2]  # eliminate the last ","
                            call += ");"
                        else:
                            # assignment operation
                            pass

                    # add argument in the set
                    for arg in arguments:
                        if arg == "a2":
                            continue
                        if PATTERN_VARIABLE.findall(arg).__len__() != 0:
                            for v in PATTERN_VARIABLE.findall(arg):
                                if v not in var_set:
                                    var_set.append(v)

            elif code[i].__contains__("setTitle"):
                call = get_complete_function_call(code, i)
                flag = False
                for var in var_set:
                    if call.__contains__(var):
                        flag = True
                if not flag:
                    continue

                # print "title", var_set
                args = extract_all_arguments(call)

                var_set.remove(var_set[0])
                var_set.append(args[2])

            elif code[i].__contains__("localizedString"):
                call = get_complete_function_call(code, i)
                args = extract_all_arguments(call)
                # print "string", var_set

                flag = False
                for var in var_set:
                    if call.__contains__(var):
                        flag = True
                if not flag:
                    continue

                map[current_method] = args[2].replace("@", "")

    return map


def extract_all_arguments(functioncall):
    bracket = 0
    truncate = 0
    tmp = range(functioncall.__len__())
    tmp.reverse()
    for i in tmp:
        if functioncall[i] == "(":
            bracket -= 1
            if bracket == 0:
                truncate = i
                break
        elif functioncall[i] == ")":
            bracket += 1
        elif functioncall[i] == "=":
            truncate = i
    if functioncall.__contains__(");"):
        sub = functioncall[truncate+1:-2]
    else:
        sub = functioncall
    tokens = sub.split(",")
    for i in range(0, tokens.__len__()):
        tokens[i] = deal_with_arguments(tokens[i].strip())
    return tokens


# deal with one argument to make it into executable format
def deal_with_arguments(arg):
    result = arg.replace("->", ".")
    if arg.__contains__("self"):
        # deal with object instance
        result = "a1"
    elif arg.__contains__('CFSTR('):
        # deal with string
        s = re.compile(r'\".*?\"').findall(arg)[0]
        s = s.replace('CFSTR(', "@").replace('")', '"')
        result = "@" + s
    elif arg.__contains__("&OBJC_CLASS___"):
        # deal with class instance
        result = arg.replace("&OBJC_CLASS___", "")
    elif re.compile("\d+LL").findall(arg).__len__() != 0:
        # deal with number
        result = arg.replace("LL", "")

    result = re.compile("\(.*?\)").sub("", result)

    # print result
    return result


def get_complete_function_call(code, line_index):
    end = line_index
    start = line_index

    tmp = range(0, line_index+1)
    tmp.reverse()
    for i in tmp:
        if code[i].__contains__(";") or code[i].__contains__("{") or code[i].__contains__("}") or code[i].strip() == "":
            # end of a statement
            if i == line_index:
                # ";" of itself
                if code[i].__contains__("objc_") or code[i].__contains__("-[") or code[i].__contains__("+[") or \
                code[i].__contains__("sub_"):
                    start = i
                    break
                else:
                    continue
            else:
                # previous statement
                start = i+1
                break
        elif code[i].__contains__("objc_") or code[i].__contains__("-[") or code[i].__contains__("+[") or \
                code[i].__contains__("sub_"):
            start = i
            break

        '''
        if code[i].__contains__(";"):
            if i != line_index:
                start = i+1
            else:
                start = i
            break
        elif code[i].__contains__("objc_") or code[i].__contains__("sub_"):
            start = i
            break
        '''

    bracket = 0
    for i in range(start, code.__len__()):
        bracket += code[i].count("(")
        bracket -= code[i].count(")")
        if bracket == 0:
            end = i
            break

    result = ""

    for i in range(start, end+1):
        result += code[i].replace("\n", "").strip()
    return result


def found_target_function(code, api):
    for line in code[1:]:  # exclude the first line
        if line.__contains__(api):
            if not api.startswith("sub_"):
                args = extract_all_arguments(get_complete_function_call(code, code.index(line)))
                if args.__len__() < 2:
                    # not a function call
                    continue
                if args[1].replace('"', "") == api:
                    return code.index(line)
            else:
                return code.index(line)

    return -1


if __name__ == '__main__':
    # start_tracing('-[CBPeripheral writeValue:forCharacteristic:type:]', 2)
    load_plugin('hexarm64')
    idc.Wait()

    project_path = ARGV[1]

    f = open(os.path.join(project_path, 'BackwardSlicing', 'config.json'), 'r')
    apis = json.load(f)["API"]

    for api in apis.keys():
        start_tracing(api.__str__(), int(apis.get(api)))

    Exit(0)

