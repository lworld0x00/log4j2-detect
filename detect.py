#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2021-12-10 17:22:04
# @Author  : threatbook (you@example.org)
# @Link    : link
# @Version : 1.0.0
from __future__ import print_function

import os
import argparse
import re

white_rules = [
    'ctx',
    'date',
    'env',
    'event',
    'jvmrunargs',
    'marker',
    'map',
    'project.version',
    'HOME'
]

error_rules = [
]

rule = r'\$\{(.*?)\}'


def read_log(path):
    for root, dirs, file_list in os.walk(path):
        for file_name in file_list:
            try:
                f = open(os.path.join(root, file_name), mode="r", encoding='utf-8')
            except TypeError as e:
                f = open(os.path.join(root, file_name), "r")
            finally:
                for text in f.readlines():
                    result = re.findall(rule, text)
                    if len(result) > 0:
                        for keyword in result:
                            b_found_white_key = False
                            sups_str = keyword
                            if len(sups_str) < 60:
                                if len(white_rules) == 0:
                                    print("!!!Danger!!!! %s in %s" % (keyword,os.path.join(root, file_name)))
                                for item in white_rules:
                                    if sups_str.startswith(item):
                                        b_found_white_key = True
                                        break
                                if b_found_white_key: continue
                                try:
                                    sups_str.encode('ascii').decode('ascii')
                                except UnicodeEncodeError:
                                    continue
                                except UnicodeDecodeError:
                                    continue
                                else:
                                    print("!!!Danger!!!! %s in %s" % (keyword,os.path.join(root, file_name)))

                    else:
                        for item in error_rules:
                            if item in text:
                                print("!!!DangerErr0r!!!! %s" % file_name)
                                break
                f.close


def parseArgs():
    parser = argparse.ArgumentParser(description="[Exp]!", formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", '--path', help="需要扫描的log目录; -p /xxx/log/",default='/var/log')
    args = parser.parse_args()

    return args


if __name__ == "__main__":
    args = parseArgs()
    read_log(args.path)

