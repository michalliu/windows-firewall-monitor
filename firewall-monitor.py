#!/usr/bin/python
#-*- coding: utf-8 -*-

import os,time,re,_winreg

TERM_COLOR_SUPPORT = False
try:
    from colorama import init,Fore,Back
    init()
    TERM_COLOR_SUPPORT = True
except:
    pass

def searchReg(filter_obj,main_key,sub_key):
    parent_key = _winreg.OpenKey(main_key,sub_key)
    for i in range( _winreg.QueryInfoKey(parent_key)[0] ):
        child = _winreg.OpenKey(parent_key,_winreg.EnumKey(parent_key,i))
        temp = {}
        if _winreg.QueryInfoKey(child)[1] > 0 :
            for j in range(_winreg.QueryInfoKey(child)[1]):
                value_name,value_data,value_data_type = _winreg.EnumValue(child,j)
                temp[value_name] = value_data 
            try:
                for filter_key in filter_obj.keys():
                    if not ( filter_key in temp.keys() and filter_obj[filter_key].match(temp[filter_key]) ):
                        raise Exception("not match") 
                return temp
            except:
                pass
        _winreg.CloseKey(child)
    _winreg.CloseKey(parent_key)
    return None

def getPath(s):
    envar_pattern = re.compile(r"%(\w*?)%")
    envar_repl = lambda m : os.getenv(m.groups()[0])
    return envar_pattern.sub(envar_repl,s)

#TODO
def usage():
    return \
u"""\
使用方法：\
"""

def color(attr,val):
    if not TERM_COLOR_SUPPORT:return val
    val = val.strip()
    if attr == 'action':
        if val == "ALLOW":val = Fore.GREEN + val + Fore.RESET
        elif val == "DROP":val = Fore.RED + "%-5s" % val + Fore.RESET
    elif attr == 'path':
        if val == "SEND":val = Fore.CYAN + "%-7s" % val + Fore.RESET
        elif val == "RECEIVE":val = Fore.MAGENTA + val + Fore.RESET
    elif attr == "sourceIP" or attr == "destIP":
        val = Fore.WHITE + Back.BLUE + "%-15s" % val + Fore.RESET + Back.RESET
    elif attr == "sourcePort" or attr == "destPort":
        val = Fore.YELLOW + Back.BLUE + "%-5s" % val + Fore.RESET + Back.RESET
    return val

def format(s,filter=['date=ANY',"time=ANY",'action=ANY','protocol=ANY','sourceIP=ANY','destIP=ANY','sourcePort=ANY','destPort=ANY','size=ANY','path=ANY']):
    result = []
    if s:
        s.strip()
        s = s.split(' ')
        temp = {}
        temp["date"] = s[0]
        temp["time"] = s[1]
        temp["action"] = s[2]
        temp["protocol"] = s[3]
        temp["sourceIP"] = s[4]
        temp["destIP"] = s[5]
        temp["sourcePort"] = s[6]
        temp["destPort"] = s[7]
        temp["size"] = s[8]
        temp["path"] = s[-1]
        for i,p in enumerate(filter):
            condition = p.split('=')
            attr = condition[0]
            val = condition[1]
            if attr in temp:
                #免死金牌
                if val.lower() == "any":
                    result.append(color(attr,temp[attr]))
                else:
                    #TODO:更复杂的条件判断支持，目前仅仅判断是否严格相等
                    if val == temp[attr]:
                        result.append(color(attr,val))
                    else:#有一个条件不满足即整体匹配失败
                        return []

    return " ".join(result).replace("\n",'')

def main():
    #TODO:根据不同的网络环境(家庭，公共，域)配置读取不同的log
    standard_logfile_reg = searchReg( {"LogFilePath":re.compile(r".*")}, _winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\services\\SharedAccess\\Defaults\\FirewallPolicy\\StandardProfile")
    logfile_path = getPath(standard_logfile_reg['LogFilePath'])
    if not os.path.exists(logfile_path):
        print u"错误日志在路径不存在，路径为%s，请打开windows防火墙日志。" % logfile_path
    else:
        #get_mtime = lambda p:os.stat(p).st_mtime
        #last_mtime = get_mtime(logfile_path)
        #print 'open %s' % logfile_path
        logfile = open(logfile_path,'r')
        logfile.seek(0,2)
        while True:
            line = format(logfile.readline(),display_filter)
            if len(line) > 0:print line
            time.sleep(0.1)
    
#TODO:sys.argv配置filter
if __name__ == '__main__':
    display_filter = ["time=ANY","path=ANY","protocol=ANY","action=ANY","sourceIP=ANY","sourcePort=ANY","destIP=ANY","destPort=ANY"]
    main()
