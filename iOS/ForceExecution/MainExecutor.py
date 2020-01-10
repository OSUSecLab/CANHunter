import time
import subprocess
import os
import pexpect
import re
from CycriptExecutor import CycriptExecutor
import json
import frida

# HOOK_PATH = "./Hooker.py"

# filter_list = []

#
# def start_hook_script(p):
#     proc = subprocess.Popen(['python', HOOK_PATH, p])
#     time.sleep(1)
#     return proc.pid
#
#
# def kill_hook_script(pid):
#     os.system("kill -9 " + str(pid))


# def read_path_from_file(file_name):
#     path = LogUtil.PATH
#     with open(path + file_name, 'r') as f:
#         lines = f.readlines()
#         functions = []
#         for line in lines:
#             if line == "\n":
#                 break
#             functions.append(line.replace('\n', ''))
#     return functions
#
#
# # Always delete the first path
# def delete_path_from_file(file_name):
#     path = LogUtil.PATH
#     with open(path + file_name, 'r') as f:  # read and write mode, allow you to delete the row after reading
#         lines = f.readlines()
#         try:
#             index = 0
#             for i in range(lines.__len__()):
#                 if lines[i].strip() == "":
#                     index = i
#                     break
#             with open(path + file_name, 'w') as o:
#                 if index == lines.__len__() - 1:
#                     o.writelines("")  # last path
#                 else:
#                     o.writelines(lines[index+1:])
#         except Exception:
#             pass
#
#
# def is_file_empty(file_name):
#     path = LogUtil.PATH
#     with open(path + file_name, 'r') as f:
#         lines = f.readlines()
#         if lines.__len__() == 0 or lines.__len__() == 1:
#             return True
#     return False


# Given a string, determine is there a hex string inside or not (len >= 3)
def hex_greper(string):
    hexes = re.compile(r'\b[0-9A-F\s]{3,}\b').findall(string.strip())
    if hexes.__len__() == 0:
        return ""
    else:
        return hexes[0]


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


def process(appname, pro):
    # run_path_generator_in_ida(path, pro)
    try:
        executor = CycriptExecutor(pro, appname)
    except Exception as e:
        print "[*] Fail to open %s, exiting..." % appname
        return

    exec_file_path = os.path.join('../BackwardSlicing/path/', pro + '.json')
    if not os.path.exists(exec_file_path):
        print exec_file_path + " not exist!"
        return

    exec_file = open(exec_file_path, 'r')

    paths = json.load(exec_file)

    output_list = {}  # collect outputs during execution of a path

    for index in paths.keys():
        current_path = paths[index]
        car = current_path['model']
        ui = current_path['ui']
        path = current_path['path']
        arguments = []
        command = ""

        for fun in path:
            try:
                res = executor.function_executor(fun).strip()
                if res.__contains__("Error"):
                    continue
                res = hex_greper(res)
                if res != "":
                    command = res

                    # extract arguments as semantics
                    if fun.__contains__("objc_msgSend"):
                        args = extract_all_arguments(fun)
                        for arg in args:
                            if arg.__contains__('@"') and arg not in arguments:
                                # constant string
                                arguments.append(arg)

            except pexpect.TIMEOUT:

                print "[!] Reach timeout limit. Skipping..."
                executor.handle_timeout()

                '''
                # kill_hook_script(p)
                print "[!] Reach timeout limit. Attempt to retry for the first time..."
                # timeout, restart hook script
                executor.handle_timeout()
                # p = start_hook_script(appname)

                try:
                    res = executor.function_executor(fun)
                    if res not in output_list:
                        output_list.append(res)
                except pexpect.TIMEOUT:
                    # second timeout, skip this command
                    # if fun not in filter_list:
                    #    filter_list.append(fun)  # don't waste time on some classes that crash the app
                    # kill_hook_script(p)
                    executor.handle_timeout()
                    # p = start_hook_script(appname)
                    print "[!] Second timeout reached, skip function: %s" % fun
                '''

            finally:
                # if fun not in filter_list:
                #    filter_list.append(fun)
                print

        # current path finishes
        # add command and semantics
        if command.strip() != "":
            output_list[index] = {}
            output_list[index]['command'] = command
            output_list[index]['arguments'] = arguments
            output_list[index]['ui'] = ui
            output_list[index]['model'] = car

    # All paths finished
    # print json to file
    out_file_path = os.path.join('.', 'result', pro + '.json')
    with open(out_file_path, 'w') as out:
        json.dump(output_list, out)

    # kill current app process
    executor.kill_target_app(frida.get_usb_device(), executor.appname)


if __name__ == '__main__':

    start = time.time()
    f = open('config.json', 'r')
    configs = json.load(f)

    for app in configs['App']:
        app_name = app.keys()[0]
        process_name = app[app_name]
        try:
            process(app_name, process_name)
        except Exception:
            print "Exception caught! time=%f" % (time.time() - start)

        print "Finish ! time=%f" % (time.time() - start)

    # enable multi-thread
    # cores = multiprocessing.cpu_count()
    # pool = Pool(processes=cores)
    # tasks = app_dict.items()
    # pool.map(merge_processes, tasks)



