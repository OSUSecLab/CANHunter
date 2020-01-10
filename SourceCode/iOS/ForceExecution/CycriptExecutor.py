import pexpect
import re
import time
import frida
import thread
import threading
import ctypes
import inspect
import json


class CycriptExecutor:

    def __init__(self, p, appname):
        f = open('config.json', 'r')
        configs = json.load(f)

        self.User = configs['User']
        self.Password = configs['Password']
        self.Host = configs['Host']
        self.Port = configs['Port']
        self.process = p
        self.appname = appname
        self.connect = None
        self.TIMEOUT = -1
        try:
            self.pid = self.open_target_app(self.get_usb_iphone(), appname)
            self.connect_to_ios()
        except Exception as e:
            raise e

    def connect_to_ios(self):
        try:
            print "[*] Connecting to remote iOS device..."
            self.connect = pexpect.spawn('ssh %s@%s -p %s' % (self.User, self.Host, self.Port))
            self.connect.expect('password:', timeout=10)
            self.connect.sendline(self.Password)
            self.connect.expect('#', timeout=5)
            print "[*] Connection established!"

            print "[*] Opening cycript commandline for process %s..." % self.process
            self.connect.sendline("cycript -p %s" % self.pid)
            self.connect.expect('cy#', timeout=5)
            print "[*] Success, cycript receiving commands from input..."
            print
        except pexpect.TIMEOUT:
            # connection time out, we may quit the app and start over again
            self.kill_target_app(frida.get_usb_device(), self.appname)
            self.handle_timeout()
            # self.connect.sendline("killall -9 cycript")
            # self.connect.expect("[\s\S]*")
            # self.clear_buffer()

            # try:
            print "[*] Connecting to remote iOS device..."
            self.connect = pexpect.spawn('ssh %s@%s -p %s' % (self.User, self.Host, self.Port))
            self.connect.expect('password:', timeout=5)
            self.connect.sendline(self.Password)
            self.connect.expect('#', timeout=5)
            print "[*] Connection established!"

            print "[*] Opening cycript commandline for process %s..." % self.process
            self.connect.sendline("cycript -p %s" % self.process)
            self.connect.expect('cy#', timeout=5)
            print "[*] Success, cycript receiving commands from input..."
            '''
            except pexpect.TIMEOUT:
                self.kill_target_app(frida.get_usb_device(), self.appname)
                self.handle_timeout()
                print "[*] Connecting to remote iOS device..."
                self.connect = pexpect.spawn('ssh %s@%s -p %s' % (self.User, self.Host, self.Port))
                self.connect.expect('password:', timeout=5)
                self.connect.sendline(self.Password)
                self.connect.expect('#', timeout=5)
                print "[*] Connection established!"

                print "[*] Opening cycript commandline for process %s..." % self.process
                self.connect.sendline("cycript -p %s" % self.process)
                self.connect.expect('cy#', timeout=5)
                print "[*] Success, cycript receiving commands from input..."
                '''

    def execute(self, command, timeout=0.01):
        try:
            self.connect.sendline(command)
            '''
            if command.__contains__("=") or command.__contains__("alloc"):  # assign or alloc command
                self.connect.expect('\".*\"', timeout=timeout)
            elif command.__contains__("[") or command.__contains__("objc_msgSend"):  # executing function
                self.connect.expect('[\s\S]*', timeout=timeout)
            else:  # choose command
                self.connect.expect('\[.*\]', timeout=timeout)'''
            time.sleep(0.1)  # wait for result
            self.connect.expect('\r.*', timeout=timeout)  # clear user input in buffer
            result = self.connect.after.replace("\r", "").replace("\n", "").replace("cy#", "")
            result = self.no_color(result)
            result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f]').sub('', result)
            self.clear_buffer()
            if result.__contains__("-sh"):  # handle when the app abnormally exits
                self.handle_timeout()
                time.sleep(1)
            return result
        except pexpect.TIMEOUT:
            '''
            print "[!] Reach timeout limit: %d seconds. Attempt to retry for the first time..." % timeout
            # restart app
            self.open_target_app(self.get_usb_iphone(), process)
            self.connect_to_ios()
            try:
                self.connect.sendline(command)
                if command.__contains__("=") or command.__contains__("alloc"):  # assign or alloc command
                    self.connect.expect('\".*\"', timeout=timeout)
                elif command.__contains__("["):  # execution command
                    self.connect.expect('[\s\S]*', timeout=timeout)
                else:  # choose command
                    self.connect.expect('\[.*\]', timeout=timeout)
                result = self.connect.after
                result = self.no_color(result.split('\n')[-1])
                result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f]').sub('', result)
                self.clear_buffer()
                return result
            except pexpect.TIMEOUT:
                # Second timeout, just skip this function
                print "[!] Second timeout reached, skip command: %s" % command
                '''
            raise pexpect.TIMEOUT(-1)

    # restart process when timeout
    def handle_timeout(self):
        try:
            self.pid = self.open_target_app(self.get_usb_iphone(), self.appname)
            self.connect_to_ios()
        except Exception:
            self.kill_target_app(frida.get_usb_device(), self.appname)
            time.sleep(0.1)
            self.pid = self.open_target_app(self.get_usb_iphone(), self.appname)
            self.connect_to_ios()

    def clear_buffer(self):
        try:
            while not self.connect.expect(r'.+', timeout=0.01):
                pass
        except pexpect.TIMEOUT:  # no more data in the buffer
            return

    # delete all color character
    @staticmethod
    def no_color(string):
        pattern = re.compile(r'\[(\d+;|\d+)+m')
        output = re.sub(pattern, '', string)
        return output

    # prepare the string for arguments
    # input should be like: [#0xaf12345 initWithString:]
    @staticmethod
    def prepare_for_argument(string):
        # TODO temporary naive method: just use null for all parameters
        string = string.replace(":", ":nil ")
        return string

    # Try to execute a function on cycript
    # input: functionname
    # return: execution result in string format
    def function_executor(self, func):
        try:
            print "[*] Starting to execute: " + func
            res = self.execute(func)
            print "[*] Finish executing, result:  " + res
            '''
            if func.startswith("sub_"):
                print "[*] sub function: " + func + " skip execution."
                return 1
            if func.startswith("+["):
                # Static function, we don't need to create an instance
                if func.find(":") == 0:
                    # No parameter needed, just execute
                    print "[!] Final execution: %s" % func[1:]
                    self.execute(func[1:])  # drop the "+" symbol
                    return 1
                else:
                    res = self.prepare_for_argument(func)
                    print "[!] Final execution: %s" % res[1:]
                    self.execute(res[1:])
                    return 1

            elif func.startswith("-["):
                # Class function, we need to either create an object instance or get it from memory
                classname = func.split(" ")[0][2:]
                ret = self.execute("choose(%s)" % classname)
                print "choose(%s): %s" % (classname, ret)
                if not ret.__contains__("#"):
                    # no object instance found in the memory, create it
                    self.execute("[%s alloc]" % classname)
                    print "Object not found. Create class: [%s alloc]" % classname

                # object instance found, choose again
                ret = self.execute("temp = choose(%s)[0]" % classname)
                print "Assgining temp = choose(%s)[0]" % classname

                # find the address
                start = ret.find("0x")
                end = start
                for i in range(start+2, ret.__len__()):
                    if "0" <= ret[i] <= "9" or "a" <= ret[i] <= 'f':
                        continue
                    else:  # end of address
                        end = i
                        break

                if start < end:
                    address = ret[start: end]
                else:
                    address = "NULL"
                    print "Address not found, wtf?  " + ret

                print "Object found, address = %s" % address

                res = "-[temp %s]" % func.split(' ')[-1][:-1]
                res = self.prepare_for_argument(res)
                print "[!] Final execution: %s" % res[1:]
                self.execute(res[1:])
                return 1

            else:
                print "[*] Invalid function name: " + func + " skip execution"
                return 1
            '''
            return res
        except pexpect.TIMEOUT:
            # except timeout exception from execute function
            raise pexpect.TIMEOUT(-1)

    @staticmethod
    def get_usb_iphone():
        Type = 'usb'
        if int(frida.__version__.split('.')[0]) < 12:
            Type = 'tether'

        device_manager = frida.get_device_manager()
        changed = threading.Event()

        def on_changed():
            changed.set()

        device_manager.on('changed', on_changed)

        device = None
        while device is None:
            devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
            if len(devices) == 0:
                print 'Waiting for USB device...'
                changed.wait()
            else:
                device = devices[0]

        device_manager.off('changed', on_changed)

        return device

    @staticmethod
    def open_target_app(device, name_or_bundleid):
        print '[*] Starting the target app {}'.format(name_or_bundleid)

        pid = ''
        session = None
        display_name = ''
        bundle_identifier = ''
        for application in CycriptExecutor.get_applications(device):
            if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
                pid = application.pid
                display_name = application.name
                bundle_identifier = application.identifier

        try:
            if not pid:
                pid = device.spawn([bundle_identifier])
                session = device.attach(pid)
                device.resume(pid)
            else:
                session = device.attach(pid)
        except Exception as e:
            return

        return pid

    @staticmethod
    def kill_target_app(device, name_or_bundleid):
        print '[!] Attempt to kill the target app {}'.format(name_or_bundleid)
        pid = ''
        for application in CycriptExecutor.get_applications(device):
            if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
                pid = application.pid

        try:
            if pid:
                device.kill(pid)
                print "[!] Finish killing the target process of {}".format(name_or_bundleid)
                time.sleep(0.5)
        except Exception as e:
            print e


    @staticmethod
    def get_applications(device):
        try:
            applications = device.enumerate_applications()
        except Exception as e:
            print 'Failed to enumerate applications: %s' % e
            return

        return applications

    def close_connection(self):
        self.connect.logout()


def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def stop_thread(thread):
    _async_raise(thread.ident, SystemExit)

