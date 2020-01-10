import datetime


class LogUtil(object):

    PATH = "./log/"
    RESULT_PATH = "./result"

    def __init__(self, app):
        self.app = app

    def print_log(self, string):
        with open(self.PATH + 'log.txt', "a") as o:
            print >> o, string

    def print_log_with_path(self, string):
        with open(self.RESULT_PATH + self.app, "a") as o:
            print >> o, string

    def clear_log(self):
        with open(self.PATH + 'log.txt', "w") as o:
            print >> o, "",

    # given a set of functions, write them to the file
    @ staticmethod
    def print_path(funcs):
        with open(LogUtil.PATH + 'path.txt', 'a') as o:
            if funcs == "\n":
                print >> o, "\n",
            else:
                for func in funcs:
                    print >> o, func

    @ staticmethod
    def clear_path():
        with open(LogUtil.PATH + 'path.txt', 'w') as o:
            print >> o, "",

    @ staticmethod
    def delete_path_on_top():
        with open(LogUtil.PATH + 'path.txt', 'r') as o:
            data = o.read().splitlines(True)
        with open(LogUtil.PATH + 'path.txt', 'w') as fout:
            fout.writelines(data[1:])

    @staticmethod
    def get_time():
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
