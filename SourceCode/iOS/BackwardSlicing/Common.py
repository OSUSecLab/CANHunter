from idautils import *
from idaapi import *
from idc import *

BASE_API = [
    # HTTP
    "dataTaskWithRequest:completionHandler:",
    "dataTaskWithURL:completionHandler:",

    # BLE
    "writeValue:forCharacteristic:type:"
    "writeValue:for:type:"
    "writeValue:for:",
    "-[NSOutputStream write:maxLength:]"

    # Streaming
    "writeData:timeout:completionHandler:"]


filter_keywords = ["style", "animate", "animation", "hidden", "image", "opacity", "animated", "animation", "color", "date"]

filter_func_list = ["setHidden:", "addTarget:action:forControlEvents:", "setConstant:", "setEnabled:",
                    "setHighlighted:", "setText:", "setAlpha:", "setOn:", "setDisableActions:",
                    "setDuration:", "setCumulative:", "setFillMode:", "hiddenHUD:",
                    "setUserInteractionEnabled:", "setBounds:", "setFrame:", "setSelected:"]

forbitmeth = ["alloc", 'viewDidLoad', "allocWithZone:", "allowsWeakReference", "autorelease", "class", "conformsToProtocol:", "copy", "copyWithZone:", "dealloc", "debugDescription", "description", "doesNotRecognizeSelector:", "finalize", "forwardingTargetForSelector:", "forwardInvocation:", "hash", "init", "initialize", "instanceMethodForSelector:" "instanceMethodSignatureForSelector:", "instancesRespondToSelector:", "isEqual", "isKindOfClass:", "isMemberOfClass:", "isProxy", "isSubclassOfClass:", "load", "methodForSelector:", "methodSignatureForSelector:", "mutableCopy", "mutableCopyWithZone:", "performSelector:", "performSelector:withObject:", "performSelector:withObject:withObject:", "respondsToSelector:", "release", "resolveClassMethod:", "resolveInstanceMethod:", "retain", "retainCount", "retainWeakReference", "superclass", "zone", ".cxx_construct", ".cxx_destruct"]


def get_pesudocode(ea):
    try:
        cfunc = decompile(ea)
        if cfunc is None:
            print "- Error occurred: Failed to decompile!"
            return None

        funccontent = ""
        sv = cfunc.get_pseudocode()
        for sline in sv:
            funccontent += tag_remove(sline.line)
            funccontent += '\n'
    except Exception:
        funccontent = ""
    return funccontent


# Parse function name to somewhat like "selRef_write:maxLength:"
# Sample input: "write:maxLength:"
def function_name_parser(name):
    if name.startswith("sub"):
        # sub function
        return name
    else:
        # objective-c function
        return "selRef_" + name


# find all the referenced addresses of a location
# The return result includes all referenced addresses
def find_xref(address):
    xrefs = []
    names = []
    for xref in XrefsTo(address):
        if xref.frm != address:
            # handle a method references itself and remove duplicated ones
            if xrefs == []:
                xrefs.append(xref.frm)
            elif xref.frm != xrefs[-1] + 4 and xref.frm != xrefs[-1] + 8:
                xrefs.append(xref.frm)
            # name = GetFunctionName(xref.frm)
            # if name != "":
            #     if name not in names:
            #         xrefs.append(xref.frm)
            #         names.append(name)
            # else:
            #         xrefs.append(xref.frm)
    return xrefs


# truncate function name to find the referenced address
# Sample: -[ASIHTTPRequest appendPostDataFromFile:] -> appendPostDataFromFile:
def function_name_truncate(name):
    if name.__contains__("["):
        # a typical objective-c function
        return name.split(" ")[-1][:-1]
    else:
        # sub functions
        return name


# Given an address, get all the caller functions
def get_ref_func(address):

    # method 1
    '''
    func = {}
    try:
        xrefs = find_xref(address)[-1]  # first jump -> objc2_const section
    except: # No caller function
        return func

    try:
        xrefs = find_xref(xrefs)[-1]  # second jump -> objc_selrefs section
    except:
        return func

    xrefs = find_xref(xrefs)    # third jump -> caller functions

    for xref in xrefs:
        try:
            func_add = Functions(xref, xref + 1).next()
            func[GetFunctionName(func_add)] = func_add
        except Exception:
            print "- [Debug] Error while getting the function address at " % address
            break

    # returns a dict like {function_name: function_address}, representing all the xrefs for a string
    return func
    '''

    if function_name_truncate(GetFunctionName(address)) in forbitmeth:
        # skip in encounter forbidden methods
        return {}

    # method 2
    func = {}

    try:
        function_name = GetFunctionName(address)
        if function_name.__contains__("["):
            name = function_name_parser(function_name_truncate(function_name))
            ref = get_name_ea(0, name)
        else:
            name = GetFunctionName(address)
            function_name = name
            ref = get_name_ea(0, name)
    except Exception:
        # can not parse function name
        return

    xrefs = find_xref(ref)

    for x in xrefs:
        if GetFunctionName(x) != "" and GetFunctionName(x) == function_name:
            # print "duplicate!"
            continue
        if not function_name.__contains__("["):
            # sub function
            try:
                if GetFunctionName(x) == "":
                    func[str(x)] = x
                else:
                    func[GetFunctionName(x)] = x
            except Exception:
                pass
        else:
            # objc function
            if function_name.startswith("sub_"):
                # the original function is a sub function, no need to compare class name
                pass
            else:
                # check if the class name match
                class_name = function_name.split(" ")[0][2:]
                msg_send_add = find_msgsend(x)
                if msg_send_add is None:
                    # print "msg_send not found!"
                    continue
                disasm = GetDisasm(msg_send_add)

                try:
                    disa_func_call = disasm.split(";")[1].strip().replace('"', "").replace('.', "")
                except Exception:
                    disa_func_call = ""

                if disa_func_call != "":
                    if disa_func_call.split(" ")[0][2:] != class_name:  # class name not match
                        # print "class name not matching!"
                        continue

                if check_x0_register(msg_send_add, class_name):
                    pass
                else:
                    # print "register check fail!"
                    continue

            try:
                func[GetFunctionName(x)] = x
            except Exception:
                pass

    for f in func.keys():
        # remove duplicate items
        if func.keys().count(f) > 1:
            del func[f]

    # returns a dict like {function_name: function_address}, representing all the xrefs for a string
    return func


# check x0 register
def check_x0_register(address, class_name):
    start = GetFunctionAttr(address, FUNCATTR_START)  # start address of the current function
    current_reg = "X0"
    ran = range(start, address)
    ran.reverse()
    for add in ran:
        if GetOpnd(add, 0) == current_reg:
            if GetMnem(add) == "MOV":
                current_reg = GetOpnd(add, 1)
            elif GetMnem(add) == "LDR":
                current_reg = GetOpnd(add, 1)
                if current_reg.__contains__("classRef"):
                    current_reg = current_reg.split(",")[-1].replace("#classRef_", "").replace("@PAGEOFF]", "")
                    if current_reg == class_name:
                        return True
                    else:
                        # can not deal with these ...
                        return False
                else:
                    return True
    if current_reg == "X0":
        c = GetFunctionName(address).split(" ")[0][2:]
        if c == class_name:
            return True
        else:
            return False
    else:
        return False


# follow the address until find the msgsend function
def find_msgsend(address):
    end = GetFunctionAttr(address, FUNCATTR_END)  # end address of the function
    if end == 18446744073709551615:
        return None
    curr_reg = GetOpnd(address, 0)                # current register that stores the selector
    if curr_reg == "X1":                          # determine whether selector is loaded into X1 or not
        flag = True
    else:
        flag = False

    # go through the disassemble till the end of the function
    for add in range(address, end):
        # find position when the selector in loaded into X1, then the next msgSend is our target
        if GetOpnd(add, 1).__contains__(curr_reg):
            mnem = GetMnem(add)
            if mnem == "MOV" or mnem == "LDR":                   # update current register
                curr_reg = GetOpnd(add, 0)
                if curr_reg == "X1":
                    flag = True

        if flag and GetOpnd(add, 0) == "_objc_msgSend":
            return add
    return None
