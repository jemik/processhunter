# processhunter
Tool for threat hunting and IR.

Processhunter is written in Python, and tested on Windows, Linux and OSX. 

This tool was created to provide threat hunters / incident responders, with context, when looking for suspicious running processes.
### Features
<ul>
	<li>Hunt with <a href="https://virustotal.github.io/yara/">Yara</a> rule(s)</li>
<li>Hunt by process name</li>
<li>Hunt by IPv4 address</li>
<li>Dump all running processes</li>
</ul>

The output is in JSON, and processes mached will contain additional information, like process ancenstors, net connections,files hashes and process children.

### Usage

```
usage: process_hunter.py [-h] [-p PID] [-r YARARULE] [-i IPADDRES] [-s PROCNAME] [-f]

optional arguments:
  -h, --help            show this help message and exit
	-p PID, --pid PID     Process id
	-r YARARULE, --rule YARARULE Yara rule
	-i IPADDRES, --ip IPADDRES Ipv4 address
	-s PROCNAME, --proc PROCNAME Process name
	-f, --full            Dump running processes
```
```
git clone https://github.com/jemik/processhunter.git
cd processhunter
sudo -H pip install -r requirements.txt
sudo ./process_hunter.py -h
```


### DISCLAIMER
This tool comes without ANY warranty! <br />
USE AT YOUR OWN RISK.

