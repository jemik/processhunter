#!/usr/bin/python

__author__ = "Jesper Mikkelsen"
__license__ = "GNU General Public License 3.0"
__version__ = "1.0.0"
"""
This tool comes WITHOUT ANY WARRANTY
USE AT YOUR OWN RISK
"""
import os
import platform
import sys
import string
import psutil
import yara
import hashlib
import argparse
import socket
import time
import re
import pefile
import json
import datetime
import uuid
import platform
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
AF_INET6 = getattr(socket, 'AF_INET6', object())
proto_map = {
    (AF_INET, SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET, SOCK_DGRAM): 'udp',
    (AF_INET6, SOCK_DGRAM): 'udp6',
}

proc_ancestors = []
process_report = []
yara_report = []
children = []
counter = 0
def Get_Proc_details(PID):
    p = psutil.Process(PID)
    try:
        ptime = datetime.datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S")
    except:
        ptime = "NA"
    try:
        pname = p.name()
    except:
        pname = "NA"
    try:
        pcmd = str(' '.join(p.cmdline()))
    except:
        pcmd = "NA"
    try:
        ppath = p.exe()
    except:
        ppath = "NA"
    proc_details = ptime, pname, pcmd, ppath
    return proc_details


def get_hash(filename):
    try:
        fh = open(filename, 'rb')
        m = hashlib.md5()
        s = hashlib.sha1()
        s256 = hashlib.sha256()

        while True:
            data = fh.read(8192)
            if not data:
                break

            m.update(data)
            s.update(data)
            s256.update(data)

        md5  = m.hexdigest()
        sha1 = s.hexdigest()
        sha256 = s256.hexdigest()
        hash_info = md5.upper(), sha1.upper(), sha256.upper()
        return hash_info
    except:
        hash_info = "NA", "NA", "NA"
        return hash_info


def Get_ProcConnections(PID):
    pnet = []
    try:
        for c in psutil.net_connections(kind='inet'):
            laddr = "%s:%s" % (c.laddr)
            raddr = ""
            alert = ""
            if c.raddr:
                raddr = "%s:%s" % (c.raddr)
                if PID == c.pid:
                    pnet.append({"proto": proto_map[(c.family, c.type)].upper(), "lhost": laddr, "rhost":raddr , "state": c.status, "pid": c.pid})

    except:
        pass
    return pnet
def GetProcParrent(pid):

    try:
        p = psutil.Process(pid)
        ptime, pname, pcmd, ppath = Get_Proc_details(p.ppid())
        md5, sha1, sha256  = get_hash(ppath)
        hash_info = {"md5": md5, "sha1": sha1, "sha256": sha256}
        proc_ancestors.insert(0,{"Creation time": ptime,"pid": p.ppid(),"childpid": p.pid, "name": pname, "cmd":  pcmd, "path": ppath, "hash": hash_info, "check_signed_detailed": check_signed_detailed(ppath), "connections": Get_ProcConnections(p.ppid())})
        #print ("My Parent: PPID: %s ChildPid: %s Name: %s CMD: %s Path: %s" % (p.ppid(), p.pid,Get_Proc_details(p.ppid()), GetProc_Cmd(p.ppid()), GetProc_Path(p.ppid()) ))
        if p.ppid() is not 0:
            GetProcParrent(p.ppid())
    except:
        pass

def GetProcChildren(PID):

    try:
        p = psutil.Process(PID)
        for c in p.children(recursive=True):

            ptime, pname, pcmd, ppath = Get_Proc_details(c.pid)
            md5, sha1, sha256  = get_hash(ppath)
            hash_info = {"md5": md5, "sha1": sha1, "sha256": sha256}
            children.append({"Creation time": ptime,"pid": c.pid, "ppid": c.ppid(),"name": pname, "cmd":  pcmd, "path": ppath, "hash": hash_info, "check_signed_detailed": check_signed_detailed(ppath), "connections": Get_ProcConnections(c.pid)})
    except:
        pass
    return children

def ScanReport(PID):
    global counter
    global proc_ancestors
    global children
    GetProcParrent(PID)
    GetProcChildren(PID)
    ptime, pname, pcmd, ppath = Get_Proc_details(PID)
    md5, sha1, sha256  = get_hash(ppath)
    hash_info = {"md5": md5, "sha1": sha1, "sha256": sha256}
    process_report.append({"Root": counter,
                    "Creation_time": ptime,
                    "Process_id": PID,
                    "Process_cmd": pcmd,
                    "Process_name": pname,
                    "Process_path": ppath,
                    "yara": yara_report,
                    "hash_info": hash_info,
                    "Process_ancestors": proc_ancestors,
                    "Process_children": children,
                    "check_signed_detailed": check_signed_detailed(ppath),
                    "Process_connections": Get_ProcConnections(PID)
                    })
    counter +=1
    proc_ancestors = []
    children = []
def YaraScan(yararule):

    global yara_report
    description = "na"
    reference = "na"
    try:
        rules = yara.compile(filepath=yararule)
        own_pid = os.getpid()
        own_ppid = psutil.Process(os.getpid()).ppid()
        for p in psutil.process_iter():
            if p.pid != own_pid or p.pid != own_ppid:
                try:
                    rule_match = rules.match(pid=p.pid)
                except:
                    continue
            if rule_match:
                for _m in rule_match:
                    if hasattr(_m, "meta"):
                        if 'description' in _m.meta:
                            description = _m.meta['description']
                        if 'reference' in _m.meta:
                            reference = _m.meta['reference']

                    yara_report = ({"matched_rule": _m.rule,
                                    "description": description,
                                    "reference": reference,
                                    "matched_string": GetMatchedStrings(_m.strings)

                    })

                ScanReport(p.pid)
                yara_report = []
    except:
        pass
def GetMatchedStrings(strings):
    strings_matched = []
    string_cache = []
    printable = set(string.printable)
    try:
        for _s in strings:
            getstring = _s[2]
            if not getstring in string_cache:
                strings_matched.append({"string": filter(lambda x: x in printable, getstring)})
                string_cache.append(getstring)
    except:
        pass
    return strings_matched

def FullProcDump():
    try:
        own_pid = os.getpid()
        own_ppid = psutil.Process(os.getpid()).ppid()
        for p in psutil.process_iter():
            if p.pid != own_pid or p.pid != own_ppid:
                ScanReport(p.pid)
    except:
        pass

def GetProcByName(searchstring):
    try:
        own_pid = os.getpid()
        own_ppid = psutil.Process(os.getpid()).ppid()
        for p in psutil.process_iter():
            if p.pid != own_pid or p.pid != own_ppid:
                #if re.search(str(p.name()),str(searchstring), re.IGNORECASE):
                if str(searchstring).lower() in str(p.name()).lower():
                    ScanReport(p.pid)

    except:
        pass

def IpScan(ipaddr):
    pid_cache = []
    try:
        own_pid = os.getpid()
        own_ppid = psutil.Process(os.getpid()).ppid()
        for c in psutil.net_connections(kind='inet'):
            laddr = "%s:%s" % (c.laddr)
            raddr = ""
            alert = ""
            if c.raddr:
                raddr = "%s:%s" % (c.raddr)
                if c.pid != own_pid or c.pid != own_ppid:
                    if c.pid not in pid_cache:
                        if re.match(str(c.raddr[0]),str(ipaddr), re.IGNORECASE):
                            ScanReport(c.pid)
                            pid_cache.append(c.pid)
    except:
        pass


# Check  if PE is signed. windows onlyfiles

def check_signed_detailed(imagepath):
	# Virtual Address
    if str(platform.system()) == "Windows":
        pe =  pefile.PE(imagepath)
        cert_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

    	# Size
        cert_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

        if cert_address != 0 and cert_size !=0:
            signature = pe.write()[cert_address+8:]
            cert_md5  = hashlib.md5(signature).hexdigest()
            cert_sha1 = hashlib.sha1(signature).hexdigest()
            signed = True
            return {"virtual_address": cert_address, "block_size": cert_size, "hash_md5": cert_md5, "hash_sha1": cert_sha1, "signed": signed}
        else:
            return {"signed": "False"}
    else:
        return {}


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='Process analysis tool')
        parser.add_argument('-p' , '--pid', action='store',dest='pid',help='Process id', required=False)
        parser.add_argument('-r' , '--rule', action='store',dest='yararule',help='Yara rule', required=False)
        parser.add_argument('-i' , '--ip', action='store',dest='ipaddres',help='Ipv4 address', required=False)
        parser.add_argument('-s' , '--proc', action='store',dest='procname',help='Process name', required=False)
        parser.add_argument("-f","--full", help="Dump running processes",action="store_true")
        args = parser.parse_args()
        client_uuid = str(uuid.uuid4())
        report_time = str(datetime.datetime.now())
        client_hostname = platform.node()
        if args.pid:
            ScanReport(int(args.pid))
            print(json.dumps([{"Report_time": report_time,
                            "Client_hostname": client_hostname,
                            "Client_UUID": client_uuid,
                            "Client_OS": str(platform.system()),
                            "Process_analysis": process_report
                            }],
                            indent=4, separators=(',', ': ')))
        elif args.yararule:
            YaraScan(args.yararule)
            print(json.dumps([{"Report_time": report_time,
                            "Client_hostname": client_hostname,
                            "Client_UUID": client_uuid,
                            "Client_OS": str(platform.system()),
                            "Process_analysis": process_report
                            }],
                            indent=4, separators=(',', ': ')))
        elif args.full:
            FullProcDump()
            print(json.dumps([{"Report_time": report_time,
                            "Client_hostname": client_hostname,
                            "Client_UUID": client_uuid,
                            "Client_OS": str(platform.system()),
                            "Process_analysis": process_report
                            }],
                            indent=4, separators=(',', ': ')))
        elif args.ipaddres:
            IpScan(args.ipaddres)
            print(json.dumps([{"Report_time": report_time,
                            "Client_hostname": client_hostname,
                            "Client_UUID": client_uuid,
                            "Client_OS": str(platform.system()),
                            "Process_analysis": process_report
                            }],
                            indent=4, separators=(',', ': ')))
        elif args.procname:
            GetProcByName(args.procname)
            print(json.dumps([{"Report_time": report_time,
                            "Client_hostname": client_hostname,
                            "Client_UUID": client_uuid,
                            "Client_OS": str(platform.system()),
                            "Process_analysis": process_report
                            }],
                            indent=4, separators=(',', ': ')))
        else:
            parser.print_help()
            sys.exit(0)
    except KeyboardInterrupt:
        print ("\nTerminated by user!!")
