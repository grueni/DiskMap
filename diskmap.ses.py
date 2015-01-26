#!/usr/bin/env python
#-*- coding: utf-8 -*-
#
#
# Copyright (C) 2011 Sébastien Wacquiez
# Copyright (C) 2015 Andreas Grüninger
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
import subprocess, re, os, sys, readline, cmd, pickle, glob, json
import unittest
from pprint import pformat, pprint
from socket import gethostname

VERSION="0.21"

LOGLEVEL_ERROR=1
LOGLEVEL_INFO=2
LOGLEVEL_WARN=3
LOGLEVEL_DEBUG=4

loglevel=LOGLEVEL_INFO
pools2Ignore = [ 'rpool','rpool1' ]

pj = os.path.join

hostname = gethostname()

cachefile = "/tmp/pouet"

prtconf = "/usr/sbin/prtconf"
zpool = "/usr/sbin/zpool"
smartctl = "/usr/local/sbin/smartctl"
mdb = "/usr/bin/mdb"
cfgadm = "/usr/sbin/cfgadm"
sasinfo="/usr/sbin/sasinfo"
sg_ses="sg_ses"
sg_readcap="sg_readcap"

def serialize_instance(obj):
  d = { '__classname__' : type(obj).__name__ }
  d.update(vars(obj))
  return d

def isLogErrorEnabled():
  return True if loglevel >= LOGLEVEL_ERROR else False

def isLogInfoEnabled():
  return True if loglevel >= LOGLEVEL_INFO else False

def isLogWarnEnabled():
  return True if loglevel >= LOGLEVEL_WARN else False

def isLogDebugEnabled():
  return True if loglevel >= LOGLEVEL_DEBUG else False

def run(cmd, args, tosend=""):
    if not isinstance(args, list):
        args = [ args ]
    # if not os.path.exists(cmd):
        # raise Exception("Executable %s not found, please provide absolute path"%cmd)
    args = tuple([ str(i) for i in args ])
#    pprint(args) 
    if tosend:
        process = subprocess.Popen((cmd,) + args,
                  stdout=subprocess.PIPE,
                  stdin=subprocess.PIPE)
        return process.communicate(tosend)[0]
    else:
        return subprocess.Popen((cmd,) + args,
               stderr=subprocess.STDOUT,
               stdout=subprocess.PIPE).communicate()[0]   

def revert(mydict):
    return dict([ (v,k) for k,v in mydict.items()])

def cleandict(mydict, *toint):
    result = {}
    for k in mydict.keys():
        if k in toint:
            result[k] = long(mydict[k])
        elif isinstance(mydict[k], str):
            result[k] = mydict[k].strip()
        else:
            result[k] = mydict[k]
    return result

def megabyze(i, fact=1000):
    """
    Return the size in Kilo, Mega, Giga, Tera, Peta according to the input.
    """
    i = float(i)
    for unit in "", "K", "M", "G", "T", "P":
        if i < 2000: break
        i = i / fact
    return "%.1f%s"%(i, unit)

class TestConfigs(unittest.TestCase):
    pass

class MyEncoder(json.JSONEncoder):

    def default(self, obj):
        print 'default(', repr(obj), ')'
        # Convert objects to a dictionary of their representation
        d = { '__class__':obj.__class__.__name__,
              '__module__':obj.__module__,

              }
        d.update(obj.__dict__)
        return d

class SesManager(cmd.Cmd):
    def __init__(self, *l, **kv):
        cmd.Cmd.__init__(self, *l, **kv)
        self._targetportaddresses = {}
        self._controllers = {}
        self._enclosures = {}
        self._disks = {}
        self._aliases = {}
        self.prompt = "Diskmap - %s> "%hostname

    @property
    def disks(self):
        return dict([ (k, v) for k, v in self._disks.items() if k.startswith("/dev/rdsk/") ])

    @property
    def targetportaddresses(self):
        return self._targetportaddresses

    @property
    def enclosures(self):
        return self._enclosures

    @property
    def controllers(self):
        return self._controllers

    @property
    def aliases(self):
        return self._aliases

    def emptyline(self):
        self.do_help("")
		  
    def ledparse(self, value, line):
        line = line.strip()
        targets = []
        if line == "all":
            targets = self.disks
        else:
            # Try to see if it's an enclosure
            target = self.get_enclosure(line)
            if target:
                targets = [ disk for disk in self.disks.values() if disk["enclosure"] == target ]
            else:
                # Try to see if it's a disk
                targets = self.get_disk(line)
        
        if targets:
            self.set_leds(targets, value)
        else:
            print "Could not find what you're talking about"

    def smartctl(self, disks, action="status"):
        """ Execute smartctl on listed drive. If no drive selected, run it on all available drive. """
        params = [ "-s", "on", "-d", "sat" ]
        if action == "status":
            params += [ "-a" ]
        elif action == "test":
            params += [ "-t", "short" ]
        result = []
        progress = xrange(1,len(disks)+1, 1).__iter__()
        for disk in disks:
            print "\rExecuting smartcl on %s : %3d/%d"%(disk["device"].replace("/dev/rdsk/",""),
                                                     progress.next(),len(disks)),
            smartparams = params + [ disk["device"]+"p0" ]
            result.append(run(smartctl, smartparams))
        print "Done"
        return result

    def preloop(self):
        try:
            self.do_load()
        except:
            print "INFO  Loading of previous save failed, trying to discover"
            self.do_discover()
            self.do_save()

    def complete_ledon(self, text, line, begidx, endidx):
        candidates = [ "all", "ALL" ]
        candidates.extend(self.aliases.values())
        candidates.extend([ disk["device"].replace("/dev/rdsk/", "") for disk in self.disks.values() ])
        candidates.extend([ disk["serial"] for disk in self.disks.values() ])
        candidates.extend([ "%(controller)s:%(enclosureindex)s:%(slot)s"%disk for disk in self.disks.values() ])
        candidates.extend([ "%(controller)s:%(index)s"%enclosure for enclosure in self.enclosures.values() ] )
        candidates.sort()
        return [ i for i in candidates if i.startswith(text) ]
	  
    def complete_alias(self, text, line, begidx, endidx):
        if line.startswith("alias -r "):
            return ([ i for i in self.aliases.keys() if i.startswith(text) ] +
                    [ i for i in self.aliases.values() if i.startswith(text) ])
        if line.count(" ") == 1:
            result = []
            result.extend(self.enclosures.keys())
            result.extend([ "%(controller)s:%(index)s"%e for e in self.enclosures.values() ])
            return [ i for i in result if i.startswith(text) ]

    complete_ledoff = complete_ledon
				
    def discover_controllers(self, fromstring=None):
        """ Discover controller present in the computer """
        if not fromstring : fromstring = run(sasinfo, ["hba","-v"])
        ctrls = fromstring.split("HBA Name:")
        for ctrl in ctrls:
            if not ctrl.strip(): continue
            for m in re.finditer(" (?P<id>[^\n]+)\n *"
                                 "Manufacturer: (?P<manufacturer>[^\n]+)\n *"
                                 "Model:  (?P<model>[^\n]+)\n *"
                                 "Firmware Version: (?P<firmwareversion>[^\n]+)\n *"
                                 "FCode/BIOS Version: (?P<biosversion>[^\n]+)\n *"
                                 "Serial Number: (?P<serial>[^\n]+)\n *"
                                 "Driver Name: ?(?P<drivername>[^\n]+)\n *"
                                 "Driver Version: (?P<driverversion>[^\n]+)\n *"
                                 "Number of HBA Ports: (?P<hbaports>[^\n]+)\n *"
                                 , ctrl):
               if m:
                   m = cleandict(m.groupdict(), "hbaports")
                   self._controllers[m["id"]] = m

    def discover_enclosures(self, ctrls = None):
        """ Discover enclosure wired to controller. Ctrls = { 0: 'sas2ircu output', 1: 'sas2ircu output', ...}"""
        if isLogInfoEnabled(): print "INFO  discover_enclosures"
        keys = {}
        enclosures2 = {}

        fromstring = run(sasinfo,[ "lu","-v" ])
        items = fromstring.split("OS Device Name:") 
        for item in items:
            if not item.strip(): continue
            for m in re.finditer(" (?P<device>[^\n]+)\n *"
                                 "HBA Port Name: (?P<hbaportname1>[^\n]+)\n *"
                                 "Target Port SAS Address: (?P<tpsa1>[^\n]+)\n *"
                                 "LUN: (?P<lun1>[^\n]+)\n *"
                                 "HBA Port Name: (?P<hbaportname2>[^\n]+)\n *"
                                 "Target Port SAS Address: (?P<tpsa2>[^\n]+)\n *"
                                 "LUN: (?P<lun2>[^\n]+)\n *"
                                 "Vendor: ?(?P<vendor>[^\n]+)\n *"
                                 "Product: (?P<model>[^\n]+)\n *"
                                 "Device Type: (?P<devicetype>[^\n]+)\n *"
                                 , item):
               if m:
                   m = cleandict(m.groupdict(), "lun")
                   if "Disk Device" == m["devicetype"] and m["device"][-2:] == "s2":
                      m["device"] = m["device"][:-2]
                   if "Disk Device" == m["devicetype"]:                      
                      self._disks[m["device"]] = {
                           "device"         : m["device"],
                           "vendor"         : m["vendor"],
                           "model"          : m["model"],
                           "devicetype"     : m["devicetype"],
                           "controller"     : 0,
                           "sizemb"         : 0,
                           "state"          : "....",
                           "slot"           : -1,
                           "enclosure"      : "????",
                           "serial"         : "????",
                           "enclosureindex" : -1,
                           }
                      self._targetportaddresses[m["tpsa1"]] = {"device": m["device"], "targetportaddress": m["tpsa1"],}
                      self._targetportaddresses[m["tpsa2"]] = {"device": m["device"], "targetportaddress": m["tpsa2"],}

        for item in items:
            if not item.strip(): continue
            for m in re.finditer(" (?P<device>[^\n]+)\n *"
                                 "HBA Port Name: (?P<hbaportname1>[^\n]+)\n *"
                                 "Target Port SAS Address: (?P<tpsa1>[^\n]+)\n *"
                                 "LUN: (?P<lun1>[^\n]+)\n *"
                                 "Vendor: ?(?P<vendor>[^\n]+)\n *"
                                 "Product: (?P<model>[^\n]+)\n *"
                                 "Device Type: (?P<devicetype>[^\n]+)\n *"
                                 , item):
               if m:
                   m = cleandict(m.groupdict(), "lun")
                   if "Disk Device" == m["devicetype"] and m["device"][-2:] == "s2":
                      m["device"] = m["device"][:-2]
                   if "Disk Device" == m["devicetype"]:
                      self._disks[m["device"]] = {
                           "device"         : m["device"],
                           "vendor"         : m["vendor"],
                           "model"          : m["model"],
                           "devicetype"     : m["devicetype"],
                           "controller"     : 0,
                           "sizemb"         : 0,
                           "state"          : "....",
                           "slot"           : -1,
                           "enclosure"      : "????",
                           "serial"         : "????",
                           "enclosureindex" : -1,
                           }
                      self._targetportaddresses[m["tpsa1"]] = {"device": m["device"], "targetportaddress": m["tpsa1"],}
							 
        enclosureindex = 0
        fromstring = run(cfgadm,[ "-la" ])
        items = fromstring.split("\n")
        for item in items:
            if not item.strip(): continue
            if not "es/ses" in item: continue
            device = " "
            words = item.split()
            if len(words) > 0:
               words = words[0].split("::")
               if len(words) > 1:
                  device = "/dev/%s"%(words[1])
            if device == " ": continue
            if isLogDebugEnabled(): print "DEBUG %s -p 0x1 %s"%(sg_ses,device)
            fromstring = run(sg_ses, ["-p","0x1",device] )
            keep = 0
            items2 = fromstring.split("Subenclosure identifier:") 
            for item2 in items2:
               keep += 1
               if keep == 1: continue
               for m in re.finditer(r" (?P<sid>[^\n]+) \(primary\)\n *"
                  "relative ES process id: (?P<repi>[^\n]+), number of ES processes: (?P<nep>[^\n]+)\n *"
                  "number of type descriptor headers: (?P<ntdh>[^\n]+)\n *"
                  "enclosure logical identifier \(hex\):(?P<lid>[^\n]+)\n *"
                  "enclosure vendor: (?P<vendor>[^\n]+)product: (?P<product>[^\n]+)rev: (?P<rev>[^\n]+)\n *"
                  , item2):
                  if m:
                     m = cleandict(m.groupdict(), "enclosures")
                     self._enclosures[device] = {}
                     self._enclosures[device]["logicalid"] = m['lid'] 
                     if m['lid'] not in enclosures2:
                        enclosures2[m['lid']] = enclosureindex
                        enclosureindex += 1
#                        print "enclosures2=%s enclosureindex=%s logicalid=%s"%(enclosures2[words[1]],enclosureindex,self._enclosures[key]["logicalid"])
                     self._enclosures[device]["enclosureindex"] = enclosures2[m['lid']]
                     self._enclosures[m['lid']] = {}
                     self._enclosures[m['lid']]["vendor"] = m['vendor']
                     self._enclosures[m['lid']]["model"] = m['product']
                     self._enclosures[m['lid']]["firmware"] = m['rev']
                     self._enclosures[m['lid']]["enclosureindex"] = enclosures2[m['lid']]
 
        keys.clear()
        for key in self._enclosures.keys():
           if "/dev/es" in key: 
              keys[key] = key

        for device in keys:
           fromstring = run(sg_ses, ["-p","0xa",device] )
#          error in sg_ses, suppress th additional output
           fromstring = fromstring.replace("<<<additional: response too short>>>\n","")
           items = fromstring.split("\n")
           for item in items:
               if not item.strip(): continue
               if "bay number" in item or "device slot number" in item:
                  words = item.strip().split(":")
                  slot = words[3].strip()
               elif "SAS address" in item and not "attached SAS address" in item:
                  words = item.strip().split(":")
                  tspa = words[1][3:]
                  if "0000000000000000" == tspa: continue
                  if tspa in self._targetportaddresses and self._targetportaddresses[tspa]["device"] in self._disks:
                     disk = self._disks[self._targetportaddresses[tspa]["device"]]
                     disk["slot"] = int(slot)
                     disk["enclosure"] = self._enclosures[device]["logicalid"]
                     disk["enclosureindex"] = self._enclosures[device]["enclosureindex"]
                  elif isLogWarnEnabled():
                     if tspa not in self._targetportaddresses: 
                        print "WARN  got targetsourceprotaddress from %s but can't be found in enclosure (may be ignored) tpa=%s device=%s"%(sg_ses,tspa,device)
                     else:
                        print "WARN  not in disks (may be ignored) tspa=%s device=%s"%(tspa,device)
       
    def discover_mapping(self, fromstring=None):
        """ use prtconf to get real device name using disk serial """
        if isLogInfoEnabled() : print "INFO  discover_mapping"
        if not fromstring : fromstring = run(prtconf, "-v")
        diskpaths = {}
        tmp1 = run(cfgadm, "-la" )
        tmp1 = tmp1.split()
        for word in tmp1:
            if "::" in word and "," in word:
               path = word.split("::")[1].split(",")[0]
               if path not in diskpaths:
                  diskpaths[path] = word

        # Do some ugly magic to get what we want
        # First, get one line per drive
        tmp = fromstring.replace("\n", "").replace("disk, instance", "\n")
        # Then match with regex for dual paths
        tmp2 = re.findall("name='inquiry-serial-no' type=string items=1 dev=none +value='([^']+)'"
                         ".*?"
                         "name='target-port' type=string items=1 +value='([^']+)'"
                         ".*?"
                         "name='target-port' type=string items=1 +value='([^']+)'"
                         ".*?"
                         "dev_link=(/dev/rdsk/c[^ ]*d0)s0", tmp)
        for serial, path1, path2, device in tmp2:
            fromstring = run(sg_readcap, device)
            tmp0 = fromstring.replace("\n", "")
            tmp0 = re.findall("Device size: ([0-9a-f]+) bytes, ", tmp0)
            for sizeBytes in tmp0:
               sizemb = int(sizeBytes)/(1024*1024)
            serial = ' '.join(serial.split())

            path1 = path1.strip()
            path2 = path2.strip()
            if device in self._disks:
                cfgpath1 = ""
                cfgpath2 = ""
                if path1 in diskpaths:
                   cfgpath1 = diskpaths[path1]  
                if path2 in diskpaths:
                   cfgpath2 = diskpaths[path2]  
                self._disks[device]["serial"] = serial
                self._disks[device]["target-ports"] = " ".join([path1,path2])
                self._disks[device]["cfgpaths"] = " ".join([cfgpath1,cfgpath2])
                self._disks[device]["sizemb"] = sizemb
            elif isLogWarnEnabled():
                print "WARN  Got the serial %s from sg_readcap, but can't find it in disk detected by sasinfo (disk removed/not on backplane ?)"%serial

        # Then match with regex for single path 
        tmp1 = re.findall("name='inquiry-serial-no' type=string items=1 dev=none +value='([^']+)'"
                         ".*?"
                         "name='target-port' type=string items=1 +value='([^']+)'"
                         ".*?"
                         "dev_link=(/dev/rdsk/c[^ ]*d0)s0", tmp)
        for serial, path1, device in tmp1:
            fromstring = run(sg_readcap, device)
            tmp0 = fromstring.replace("\n", "")
            tmp0 = re.findall("Device size: ([0-9a-f]+) bytes, ", tmp0)
            for sizeBytes in tmp0:
               sizemb = int(sizeBytes)/(1024*1024)
            serial = ' '.join(serial.split())
            path1 = path1.strip()
            if device in self._disks:
                cfgpath1 = ""
                cfgpath2 = ""
                if path1 in diskpaths:
                   cfgpath1 = diskpaths[path1]
                self._disks[device]["serial"] = serial
                self._disks[device]["target-ports"] = path1
                self._disks[device]["cfgpaths"] = " ".join([cfgpath1,cfgpath2])
                self._disks[device]["sizemb"] = sizemb
            elif isLogWarnEnabled():
                print "WARN  Got the serial %s from sg_readcap, but can't find it in disk detected by sasinfo (disk removed/not on backplane ?)"%serial
					   
    def discover_zpool(self, fromstring=None):
        """ Try to locate disk in current zpool configuration"""
        if isLogInfoEnabled() : print "INFO  discover_zpool"
        if not fromstring : fromstring = run(zpool, "status")
        pools = fromstring.split("pool:")
        for pool in pools:
            if not pool.strip(): continue
            for m in re.finditer(" (?P<pool>[^\n]+)\n *" # We've splitted on pool:, so our first word is the pool name
                                 "state: (?P<state>[^ ]+)\n *"
                                 "(status: (?P<status>(.|\n)+)\n *)??"
                                 "scan: (?P<scan>(.|\n)*)\n *"
                                 "config: ?(?P<config>(.|\n)*)\n *"
                                 "errors: (?P<errors>[^\n]*)"
                                 ,pool):
                m = m.groupdict()
                if pools2Ignore.count(m["pool"].strip()) > 0: continue
                parent = "stripped"
                for disk in re.finditer("(?P<indent>[ \t]+)(?P<name>[^ \t\n]+)( +(?P<state>[^ \t\n]+) +)?("
                                        "(?P<read>[^ \t\n]+) +(?P<write>[^ \t\n]+) +"
                                        "(?P<cksum>[^\n]+))?(?P<notes>[^\n]+)?\n", m["config"]):
                    disk = disk.groupdict()
                    if not disk["name"] or disk["name"] in ("NAME", m["pool"]):
                        continue
                    if disk["name"][-4:-2] == "d0":
                        disk["name"] = disk["name"][:-2]
                    if (disk["name"].startswith("mirror") or
                        disk["name"].startswith("log") or
                        disk["name"].startswith("raid") or
                        disk["name"].startswith("spare") or
                        disk["name"].startswith("cache")):
                        parent = disk["name"].strip()
                        continue
                    if "/dev/rdsk" not in disk["name"]:
                        disk["name"] = "/dev/rdsk/%s"%disk["name"]
                    if disk["name"] not in self._disks and isLogWarnEnabled():
                        print "WARN  Got the disk %s from zpool status, but can't find it in disk detected by sas2ircu (disk removed ?)"%disk["name"]
                        continue
                    self._disks[disk["name"]]["zpool"] = self._disks[disk["name"]].get("zpool", {})
                    self._disks[disk["name"]]["zpoolstate"] = disk["state"]
                    self._disks[disk["name"]]["zpool"][m["pool"]] = parent

    def do_alias(self, line):
        """
        Used to set a name on a enclosure.
        
        Usage : alias enclosure name
                alias -r name
                alias -r enclosure
        Without parameters : list current alias
        """
        if not line:
            pprint(self.aliases)
        elif line.startswith("-r"):
            junk, alias = line.split(" ",1)
            alias = alias.strip()
            if alias in self._aliases:
                del self._aliases[alias]
            else:
                # We have to do a reverse lookup to find it !
                tmp = revert(self._aliases)
                if alias in tmp:
                    del self._aliases[tmp[alias]]
            self.do_save()
        elif " " in line:
            target, alias = line.split(" ",1)
            alias = alias.strip()
            enclosure = self.get_enclosure(target.strip())
            if not enclosure:
                print "No such enclosure %s"%target.lower()
            else:
                self._aliases[enclosure] = alias
                self.do_save()

    def do_configdump(self, path):
        if not path:
            path = pj(".", "configudump-%s"%hostname)
        if not os.path.exists(path):
            os.makedirs(path)
        tmp = run(sas2ircu, "LIST")
        self.discover_controllers(tmp)
        file(pj(path, "sas2ircu-list.txt"), "w").write(tmp)
        for ctrl in self.controllers:
            file(pj(path, "sas2ircu-%s-display.txt"%ctrl), "w").write(
                run(sas2ircu, [ctrl, "DISPLAY"]))
        file(pj(path, "prtconf-v.txt"), "w").write(
            run(prtconf, "-v"))
        file(pj(path, "zpool-status.txt"), "w").write(
            run(zpool, "status"))
        print "Dumped all value to path %s"%path	  
					 
    def do_configure_disk(self,device):
        """Configure unconfigured disks with cfgadm
        
        The mandatory parameter ist the devicename of the disk
        following /dev/rdsk/...

        """
        key = "/dev/rdsk/%s"%device
        if key in self._disks:
           disk = self._disks[key]
#           print "device=%s cfgpaths=%s target-ports=%s"%(disk["device"],disk["cfgpaths"],disk["target-ports"])
           words =  disk["cfgpaths"].split()
           for word in words:
              print "cfgadm -yc configure %s"%(word)
        else:
           print "device not found: %s"%(key)

    def do_controllers(self, line):
        """Display detected controllers"""
        pprint(self.controllers)

    def do_discover(self, configdir=""):
        """Perform discovery on host to populate controller, enclosures and disks

        Take an optional parameter which can be a directory containing files dumped
        with confidump.
        """
        self._targetportadresses = {}
        self._controllers = {}
        self._enclosures = {}
        self._disks = {}
        if configdir and os.path.isdir(configdir):
            # We wan't to load data from an other box for testing purposes
            # So we don't want to catch any exception
            files = os.listdir(configdir)
            for f in ("prtconf-v.txt", "sas2ircu-0-display.txt", "sasinfo-hba.txt", "zpool-status.txt"):
                if f not in files:
                    print "Invalid confdir, lacking of %s"%f
                    return
            self.discover_controllers(file(pj(configdir, "sasinfo-hba.txt")).read())
            files = glob.glob(pj(configdir, "sas2ircu-*-display.txt"))
            tmp = {}
            for name in files:
                ctrlid = long(os.path.basename(name).split("-")[1])
                tmp[ctrlid] = file(name).read() 
            self.discover_enclosures(tmp)
            self.discover_mapping(file(pj(configdir, "prtconf-v.txt")).read())
            self.discover_zpool(file(pj(configdir, "zpool-status.txt")).read())
        else:
            for a in ( "discover_controllers", "discover_enclosures",
                   "discover_mapping", "discover_zpool" ):
                try:
                    getattr(self, a)()
                except Exception, e:
                    print "Got an error during %s discovery : %s"%(a,e)
                    print "Please run %s configdump and send the report to dev"%sys.argv[0]
        self.do_save()
		  
    def do_disks(self, line):
        """Display detected disks. Use -d for debug output, -e for output with enclosures"""
        list = [ ("%1d:%.2d:%.2d"%(v["controller"], v["enclosureindex"], v["slot"]), v)
                 for k,v in self.disks.items() ]
        list.sort()
        if line == "-d":
            pprint(list)
            return
        totalsize = 0
        lagEnclosure = " "
        if line == "-e":
           for path, disk in list:
               disk["path"] = path.replace("-01","??")
               disk["device"] = disk["device"].replace("/dev/rdsk/", "").strip()
               disk["model"] = disk["model"].strip()
               disk["readablesize"] = megabyze(disk["sizemb"]*1024*1024)
               totalsize += disk["sizemb"]*1024*1024
               if lagEnclosure != disk["enclosure"]:
                  lagEnclosure = disk["enclosure"]
                  e = self._enclosures[disk["enclosure"]]
                  e["logicalid"] = lagEnclosure
                  print "enclosure=%(enclosureindex)s  logicalid=%(logicalid)s  %(vendor)s  %(model)s  %(firmware)s "%(e)
               if "zpool" in disk:
                  disk["pzpool"] = " / ".join([ "%s: %s"%(k,v) for k,v in disk.get("zpool", {}).items() ])
                  print "  %(path)s  %(device)23s  %(model)16s  %(serial)25s  %(readablesize)7s  %(state)s  %(pzpool)s  %(zpoolstate)s"%disk
               else:
                  print "  %(path)s  %(device)23s  %(model)16s  %(serial)25s  %(readablesize)7s  %(state)s"%disk
        else:
           for path, disk in list:
               disk["path"] = path.replace("-01","??")
               disk["device"] = disk["device"].replace("/dev/rdsk/", "").strip()
               disk["model"] = disk["model"].strip()
               disk["readablesize"] = megabyze(disk["sizemb"]*1024*1024)
               totalsize += disk["sizemb"]*1024*1024
               if "zpool" in disk:
                  disk["pzpool"] = " / ".join([ "%s: %s"%(k,v) for k,v in disk.get("zpool", {}).items() ])
                  print "%(path)s  %(device)23s  %(model)16s  %(serial)25s  %(readablesize)7s  %(state)s  %(pzpool)s  %(zpoolstate)s"%disk
               else:
                  print "%(path)s  %(device)23s  %(model)16s  %(serial)25s  %(readablesize)7s  %(state)s"%disk
        print "Drives : %s   Total Capacity : %s"%(len(self.disks), megabyze(totalsize))

    def do_disksd(self, line):
        """Display detected disks"""
        pprint(self.disks)
        for key in self.disks.keys():
             if not self.disks[key].has_key("enclosureindex"):
                 pprint(self.disks[key])      

    def do_enclosures(self, line):
        """Display detected enclosures"""
        pprint(self.enclosures)

    def do_ledoff(self, line):
        """ Turn off locate led on parameters FIXME : syntax parameters"""
        self.ledparse(False, line)

    def do_ledon(self, line):
        """ Turn on locate led on parameters FIXME : syntax parameters"""
        self.ledparse(True, line)
		  
    def do_load(self, line=cachefile):
        """Load data from cache file. Use file %s if not specified"""%cachefile
        self._controllers, self._enclosures, self._disks, self._aliases, self._targetportaddresses = pickle.load(file(line))
			  
    def do_mangle(self, junk=""):
        """ This function is automatically called when piping something to diskmap.

        It'll suffix all drive name with the enclosure name they are in (defined with an
        alias) and the drive slot.

        Try : iostat -x -e -n 1 | diskmap.py
        """
        if sys.stdin.isatty():
            print "This command is not intented to be executed in interactive mode"
            return
        replacelist = []
        for enclosure, alias in self.aliases.items():
            for disk in self.disks.values():
                if disk["enclosure"] == enclosure:
                    tmp = disk["device"].replace("/dev/rdsk/", "")
                    replacelist.append((tmp, "%s/%s%02d"%(tmp, alias, disk["slot"])))
        line = sys.stdin.readline()
        while line:
            for r, e in replacelist:
                line = line.replace(r, e)
            sys.stdout.write(line)
            sys.stdout.flush()
            line = sys.stdin.readline()

    def do_quit(self, line):
        "Quit"
        return True
	 
    do_EOF = do_quit

    do_refresh = do_discover
	 
    def do_save(self, line=cachefile):
        """Save data to cache file. Use file %s if not specified"""%cachefile
        if not line: line = cachefile # Cmd pass a empty string
        pickle.dump((self._controllers, self._enclosures, self._disks, self._aliases, self._targetportaddresses), file(line, "w+"))

    def do_smartcl_getstatus(self, line):
        # FIXME : line parsing
        if line:
            raise NotImplemetedError
        else:
            disks = self.disks.values()
        for (disk, smartoutput) in zip(disks, self.smartctl(disks)):
            try:
                self._disks[disk["device"]]["smartoutput"] = smartoutput
                smartoutput = re.sub("\n[ \t]+", " ", smartoutput)
                if "test failed" in smartoutput:
                    print "  Disk %s fail his last test"%disk["device"].replace("/dev/rdsk/", "")
                zob= re.findall("(Self-test execution status.*)", smartoutput)
            except KeyError:
                pass

    def do_smartcl_runtest(self, line):
        # FIXME : line parsing
        if line:
            raise NotImplemetedError
        else:
            disks = self.disks.values()
        self.smartctl(disks, action="test")

    def do_sd_timeout(self, timeout=""):
        """
        Get / Set sd timeout value

        When no parameter is present, display the current sd_io_time, and check that running
        drive use the same timing.
        
        This script will only change value for the running drive. If you wan't to apply change
        permanently, put 'set sd:sd_io_time=5' in /etc/system

        Be aware that the script will change the default value of sd_io_time, and also change
        the current value for all drive in your system.

        See : http://blogs.everycity.co.uk/alasdair/2011/05/adjusting-drive-timeouts-with-mdb-on-solaris-or-openindiana/
        """
        if timeout:
            try:
                timeout = int(timeout)
            except:
                print "Invalid timeout specified"
                return
        # Displaying current timeout
        tmp = run(mdb, "-k", tosend="sd_io_time::print\n")
        globaltimeout = int(tmp.strip(), 16)
        print "Current Global sd_io_time : %s"%globaltimeout
        drivestimeout = run(mdb, "-k", tosend="::walk sd_state | ::grep '.!=0' | "
                            "::print -a struct sd_lun un_cmd_timeout\n")
        values = [ int(i, 16) for i in re.findall("= (0x[0-9a-f]+)", drivestimeout) if i ]
        print "Got %s values from sd disk driver, %s are not equal to system default"%(
            len(values), len(values)-values.count(globaltimeout))
        if timeout: # We want to set new timeout for drives
            # Set global timeout
            print "Setting global timeout ...",
            run(mdb, "-kw", tosend="sd_io_time/W 0x%x\n"%timeout)
            # Set timeout for every drive
            for driveid in re.findall("(.+) un_cmd_timeout", drivestimeout):
                print "\rSetting timeout for drive id %s ..."%driveid,
                run(mdb, "-kw", tosend="%s/W 0x%x\n"%(driveid, timeout))
            print "Done"
            print "Don't forget add to your /etc/system 'set sd:sd_io_time=%s' so change persist accross reboot"%timeout
		  
    def do_targetportaddresses(self, line):
        """Display detected targetportaddresses"""
        pprint(self.targetportaddresses)

    def do_unconfigure_disk(self,device):
        """Unconfigure configured disks with cfgadm
        
        The mandatory parameter ist the devicename of the disk
        following /dev/rdsk/...

        """
        key = "/dev/rdsk/%s"%device
        if key in self._disks:
           disk = self._disks[key]
#           print "device=%s cfgpaths=%s target-ports=%s"%(disk["device"],disk["cfgpaths"],disk["target-ports"])
           words =  disk["cfgpaths"].split()
           for word in words:
              print "cfgadm -yc unconfigure %s"%(word)
        else:
           print "device not found: %s"%(key)
        
    def do_zpool_layout(self, line):
        """
        Helps to layout a ZFS pool.        
         
        zpool_layout [mirror|raidz] paritydisks datadisks [enclosure1 enclosure2 ..|startslot:maxslot:enclosure1 startslot:maxslot:enclosure2 ...]

        Zpool_layout creates the 'zpool create' command and add a commented output to proof the result.
        The argument [mirror|raidz] defines the type of the vdevs for the zpool.
        The arguments paritydisks and datadisks sum up to the width of a vdev.
        Zpool_layout distributes the disks from the enclosures sequentially and equally over the vdevs. 
        If just the wwn's of the enclosures are defined all disks are used.
        If not all of the disks of an enclosure should be used the range of slots to used can be defined as firstslot and maxslot.  

        Examples: 

        2 way mirror on 1 enclosure with 24 slots, define vdevs from consecutive slot numbers : 
        zpool_layout mirror 1 1 enclosure1
        => mirror slot0 slot1 mirror slot2 slot3 mirror ...     
        
        2 way mirror on 1 enclosure with 24 slots, define vdevs from the first and the second half of the slots :
        zpool_layout mirror 1 1 0:11:enclosure1 12:23:enclosure1
        => mirror slot0 slot12 mirror slot1 slot13 mirror ...

        2 way mirror on 2 enclosures with 24 slots, define vdevs from consecutive slot numbers, use first half of the enclosures :
        zpool_layout mirror 1 1 0:11:enclosure1 0:11:enclosure2
        => mirror slot0-enclosure1 slot0-enclosure2 mirror slot1-enclosure1 slot1-enclosure2 mirror ...

        Raidz with parity 1 and 3 data disks per vdev
        zpool_layout raidz 1 3 enclosure1
        => raidz1 slot0 slot1 slot3 slot4 raidz1 ...
        """
        line = line.strip()
        if not line: return
        line = line.split()
        vdev = line.pop(0).lower()
        parity = int(line.pop(0))
        data = int(line.pop(0))
        width = parity + data
        sumOfDisks = 0
        disks = {}
        enclosurei = 0
        for item in line:
           startslot = 0
           maxslot = 9999
           if ":" in item:
              words = item.split(":")
              if len(words)==3:
                 startslot = int(words[0])
                 maxslot = int(words[1])
                 enclosure = words[2]
           else:
              enclosure = item
           disks[enclosurei] = [ disk for disk in self.disks.values() 
               if disk["enclosure"] == enclosure and disk["slot"] >= startslot and disk["slot"] <= maxslot ]
           disks[enclosurei].sort(key=lambda a: a["slot"])
           sumOfDisks += len(disks[enclosurei])
           enclosurei += 1
#           pprint(disks[enclosure])
#      print "data=%d parity=%d width=%d startslot=%d maxslot=%d sumOfDisks=%d"%(data ,parity, width, startslot, maxslot, sumOfDisks)             
           
        # Now, iterate on each enclosures we get a print the drive device name
        commentlong = {}
        result = {}
        vdev = "mirror" if vdev == "mirror" else "%s%d"%(vdev, parity)
        for vdevcnt in range(0,int(sumOfDisks/width)):
            # Use a temporary list so we don't print partial calculation
            tmp = [ vdev ]
            commentlong[vdevcnt] = [ "%s-%d"%(vdev, vdevcnt) ]
            i = 0
            try:
                while i < width :
                    for enclosurei in disks.keys() :
#                       print "vdevcnt=%d enclosure=%s width=%d i=%d"%(vdevcnt,enclosure, width,i)
                       # Get next disk
                       disk = disks[enclosurei].pop(0)
                       # Add what we need
                       tmp.append(disk["device"].replace("/dev/rdsk/",""))
                       commentlong[vdevcnt].append("%s   %s"%( 
                          self.get_diskpath("chassis-short",disk["device"]),
                          self.get_diskpath("chassis-long",disk["device"])))
                       i += 1
                result[vdevcnt] = tmp
            except IndexError:
                    break
        print "# zpool create ???"
        text = "zpool create ???"
        for item in result.values():
           text = "%s /\n   %s"%(text," ".join(item))
        print text
        print "# zpool create ???"
        for vdev, comments in zip( result.values(),commentlong.values() ):
           what = "vdev"
           indent = "#    "
           for device, comment in zip( vdev, comments ):
              if what == "vdev" : print "%s%s /"%(indent, comment)
              else              : print "%s%s / #  %s"%(indent, device, comment)
              what = "device"
              indent = "#       "

    def do_zpool_status(self, poolname, fromstring=None):
      """ Show zpool and add location of devices
      """
      if not fromstring:
        if not poolname:
            fromstring = run(zpool, "status")
        else:
            fromstring = run(zpool, ["status",poolname])
      lines = fromstring.split("\n")
      for line in lines:
         location = " "
         words = line.strip().split()
         if (len(words) > 0):
            key = "/dev/rdsk/%s"%words[0]
            if key in self._disks:
               location = "%s  %s"%(self.get_diskpath("chassis-short",key),self.get_diskpath("chassis-long",key))
            elif "READ WRITE CKSUM" in line:
               location = "%7s  %59s"%("PATH","LOCATION")
         print "%s  %s"%(line,location)

    def get_disk(self, line):
        for t in (line, "/dev/rdsk/%s"%line, line.upper(), line.lower()):
            tmp = self._disks.get(t, None)
            if tmp:
                return [ tmp ]
    
        # Try to locate by path
        try:
            # Check if first element of path is an enclosure
            tmp = line.split(":",2)
            if len(tmp) == 2:
                e = self.get_enclosure(tmp[0])
                if e:
                    return [ disk for disk in self.disks.values()
                             if disk["enclosure"] == e and disk["slot"] == long(tmp[1]) ]
            else:
                c, e, s = tmp
                c, e, s = long(c), long(e), long(s)
                return [ disk for disk in self.disks.values()
                         if disk["controller"] == c and disk["enclosureindex"] == e
                         and disk["slot"] == s ]
        except Exception, e:
            #print e
            return None

    def get_diskpath(self, typ, key):
        d = self._disks[key]
        if typ == "chassis-short":
           return "%1d:%.2d:%.2d"%(d["controller"], d["enclosureindex"], d["slot"]) 
        elif typ == "chassis-long":
           text = "??"
           if self._enclosures.has_key(d["enclosure"]):
              e = self._enclosures[d["enclosure"]]
              l = d["enclosure"]
              if d["slot"] > 9:
                 slot = "SLOT__%d"%(d["slot"])
              else:
                 slot = "SLOT___%d"%(d["slot"])
              text = "/dev/chassis/%s-%s.%s/%s/disk"%(e["vendor"],e["model"],l,slot)
              text = text.replace(" ","_")
           return text
        else:
           return "?"
				
    def get_enclosure(self, line):
        """ Try to find an enclosure """
        aliases = revert(self.aliases)
        if line in aliases:
            line = aliases[line]
        if line in self.enclosures:
            return line
        if line.lower() in self.enclosures:
            return line.lower()
        try:
            c, e = line.split(":", 1)
            c, e = long(c), long(e)
            tmp = [ v["enclosureindex"].lower() for v in self.enclosures.values()
                    if v["controller"] == c and v["enclosureindex"] == e ]
            if len(tmp) != 1: raise
            return tmp[0]
        except Exception, e:
            #print e
            return None
				
    def set_leds(self, disks, value=True):
        if isinstance(disks, dict):
            disks = disks.values()
        progress = xrange(1,len(disks)+1, 1).__iter__()
        setorclear = "-S" if value else "-C"
        value = "on" if value else "off"
        for disk in disks:
            for key in self._enclosures.keys():
               if "/dev/" in key and self._enclosures[key]["logicalid"] == disk["enclosure"]:
                  run(sg_ses, ["-I","0,"+str(disk["slot"]-1),setorclear,"ident",key] )

    def do_test(self,line):
        result = {}
        result["Controllers"] = []
        result["EnclosureDevices"] = [] 
        result["EnclosureLogicalIds"] = []
        result["Disks"] = []
        result["Targetportaddresses"] = []
        for key in self.controllers.keys():
            result["Controllers"].append( self.controllers[key] )
        for key in self.enclosures.keys():
          if "/dev/" in key:
            result["EnclosureDevices"].append( self.enclosures[key] )
          else:
            result["EnclosureLogicalIds"].append( self.enclosures[key] )
        for key in self.disks.keys():
            result["Disks"].append( self.disks[key] )
        for key in self.targetportaddresses.keys():
            result["Targetportaddresses"].append( self.targetportaddresses[key] )

        test = json.dumps(result, sort_keys=True, indent=2)
        print test
						
    def __str__(self):
        result = []
        for i in ("controllers", "enclosures", "disks"):
            result.append(i.capitalize())
            result.append("="*80)
            result.append(pformat(getattr(self,i)))
            result.append("")
        return "\n".join(result)

if __name__ == "__main__":
    sm = SesManager()
    if len(sys.argv) > 1:
        sm.preloop()
        sm.onecmd(" ".join(sys.argv[1:]))
        sm.postloop()
    elif sys.stdin.isatty():
        sm.cmdloop()
    else:
        sm.preloop()
        sm.onecmd("mangle")
        sm.postloop()
    
    


