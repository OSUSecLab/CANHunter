# coding: utf-8
import os
import json

f = open("config.json", 'r')
config = json.load(f)

IDA_PATH = config['IDA_PATH']

PROJECT_PATH = config['PROJECT_PATH']
SCRIPT_PATH = PROJECT_PATH + "BackwardSlicing/BackwardSlicing.py"

APP_PATH = config['APP_PATH']

# execute
# cmd = '"' + IDA_PATH + '"' + ' -A -S"' + SCRIPT_PATH + '" "' + APP_PATH + '"'
for app in APP_PATH:
    cmd = '"' + IDA_PATH + '"' + ' -S"' + SCRIPT_PATH + ' %s" "' % PROJECT_PATH + app + '"'
    os.system(cmd)


