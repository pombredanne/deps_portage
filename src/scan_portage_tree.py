import os
import sys

import shlex
import sys
import re

class Portscan():

    def __init__(self, rootdir, attr_list):
        self.attr_list = attr_list
        self.rootdir = rootdir
        self.attr_len = len(attr_list)
        self.cleanning_rules = ['!.*', '-[0-9].*', '>=*', '<=*', '=', '.*\?', '[()]', '^ ','\|+', ':.*', '\[.*\]', '[\[\]]']

    def _get_other_variables(self, var):
        ret = []
        lexer = shlex.shlex(var, posix=True)
        lexer.quotes = ""
        flag = 0
        for token in lexer:
            if token == '{':
                flag = 2
            elif flag == 2:
                ret.append(token)
                flag =  0
        return ret

    def _clean_dep(self, dep):
        token = re.sub('[\t ]+', ' ', dep)
        for rule in self.cleanning_rules:
            token = re.sub(rule, '', token)
        token = re.sub('\n', '', token)
        ret = set(re.split( ' *', token))
        return ret

    def _clean_ebuild_name(self, path):
        cat = re.sub('.*/([^/]*/[^/]*/*)','\\1',path)
        return cat


    def _get_most_recent_ebuild(self, files_list):
        """return the most recent ebuild 
        or None (if threre is no ebuild)
        of a file list"""

        ebuild=None
        for f in files_list:
            if re.match('.*\.ebuild$', f):
                if not f:
                    ebuild = f
                if f > ebuild:
                    ebuild=f
        return ebuild

    def _resolv_token(self, token, attr_tmp_dic):
        attr_in_attr = self._get_other_variables(token)
        for attr in attr_in_attr:
            if attr in attr_tmp_dic:

                token = re.sub('\${' + attr +'}', attr_tmp_dic[attr], token)
            else:
                token = re.sub('\${' + attr +'}', '', token)
        return token

    def _scan_ebuild(self, root, ebuild):
        ebuild_path = os.path.join(root, ebuild) 
 
        input_file = file(ebuild_path, 'rt').read()
        lexer = shlex.shlex(input_file, posix=True)

        flag = 0
        attr_name = ''
        attr_tmp_dic = {}
        counter = self.attr_len
        for token in lexer:
            if token == '=':
                flag = True
            elif flag:
                flag = False
                attr_tmp_dic[attr_name] = self._resolv_token(token, attr_tmp_dic)
                if attr_name in self.attr_list:
                    counter = counter - 1
            else:
                attr_name = token
            if counter == 0:
                break

        ret = {}
        for attr in self.attr_list:
            if attr in attr_tmp_dic:
                if attr == 'RDEPEND' or attr == 'DEPEND':
                    ret[attr] = self._clean_dep(attr_tmp_dic[attr])
                else:
                    ret[attr] = attr_tmp_dic[attr]
            else:
                ret[attr] = ''
        return ret

    def simple_print(self, dic, ebuild):
        print('NAME: ' + ebuild)
        for attr in self.attr_list:
            if type(dic[attr]) is str:
                print(attr + ': ' + dic[attr])
            else:
                token = ''
                for val in list(dic[attr]):
                    if not val == '':
                        token = token + ' ' + val
                print(attr + ': ' + token)
        print('\n')

    def scan_portage_tree(self, rootdir, handler):
        #for each subdirectory of the portage tree
        for root, subFolders, files in os.walk(rootdir):
            ebuild = self._get_most_recent_ebuild(files)
            if not ebuild is None:
                ret = self._scan_ebuild(root, ebuild)
                handler(ret, self._clean_ebuild_name(root))

from pygraph_redis.directed_graph import Directed_graph
import redis

#creating a basic logger
import logging
logging.basicConfig(format = u'%(message)s')
logger = logging.getLogger(u'redis')
logger.parent.setLevel(logging.DEBUG)

#creating the redis connexion
r_server = redis.Redis("localhost")

#creating the graph object
deps = Directed_graph(r_server, u'deps', logger)
rdeps = Directed_graph(r_server, u'rdeps', logger)

def redis_insert(dic, ebuild):
    deps.write_on_node(ebuild,[],dic['DEPEND'], {'DESCRIPTION': dic['DESCRIPTION'], 'LICENSE': dic['LICENSE'], 'HOMEPAGE': dic['HOMEPAGE']})

rootdir = sys.argv[1]

attr_list=['RDEPEND', 'DEPEND', 'LICENSE', 'DESCRIPTION', 'HOMEPAGE']
scanner = Portscan(rootdir, attr_list)
scanner.scan_portage_tree(rootdir, redis_insert)
