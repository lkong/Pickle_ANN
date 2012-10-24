import sys
import os
import getopt
import subprocess
import socket
class datasource:
    ip_list=set()
    susip_list=set()
    source_file=""
    def get_normalize_base(self):
        cmd=[]
        #Try to run something like this:
        #nfdump -r /data/nfdump/nfcapd.current  -n 0 -s as
        cmd.extend(["nfdump","-q","-R",self.source_file,"-n","1","-o","pipe","-s","as"])
        for record in runProcess(cmd):
            if len(record)>2:
                record_array=record.split('|')
                record_dict=dict({"duration":long(record_array[3])-long(record_array[1]),"flow":record_array[7],"packets":record_array[8],"bytes":record_array[9],"pps":record_array[10],"bps":record_array[11],"bpp":record_array[12].replace('\n','')})
                return record_dict
    def __init__(self,sourcefile):
        self.source_file=sourcefile
        self.get_ipaddress_list()
        print "init ip list created"
        self.get_bt_user("tracker_ip_list")
        print "sus ip list created"
    def get_bt_user(self,tracker_ip_list):
        cmd=[]
        cmd.extend(['nfdump','-R',self.source_file,'-f',tracker_ip_list,'-q','-o','fmt:%sa'])
        for susip in runProcess(cmd):
            susip=susip[:susip.rfind("\n")]
            susip=susip.replace(' ','')
            if susip not in self.susip_list:
                self.susip_list.add(susip)
    def get_sus_dict(self,limit=0):
        count=0
        for susip in self.susip_list:
                for entry in self.get_input_per_ipaddress(susip):
                    yield entry
                    count+=1
                    if count==limit and limit!=0:
                        return
    def get_non_sus_dict(self,limit=0):
        count=0
        for ip in self.ip_list:
            if ip not in self.susip_list:
                for entry in self.get_input_per_ipaddress(ip):
                    yield entry
                    count+=1
                    if count==limit and limit!=0:
                        return

    def get_ipaddress_list(self):
        # process arguments
        #for arg in args:
        #output a list of ip address to the output file
        tempString ="nfdump -R "+self.source_file + " -o fmt:%sa >> tempfile"
        os.system(tempString)
        print "ip list dumped to tempfile"
        tempfile=open("tempfile",'r')
        for line in tempfile:
            if line.find(".",line.find(".")+1)-line.find(".")==4:
                if line not in self.ip_list: # not a duplicate
                        self.ip_list.add(line)
        os.remove("tempfile")
    def get_input_per_ipaddress(self,ip):
        #sourcePath=self.source_file[:self.source_file.rfind('/')+1]
        #dumper=pynfdump.Dumper(sourcePath)
        #dumper.set_where(dirfiles=10)
        if '\n' in ip:
            ip=ip.replace('\n','')
        ip=ip.replace(' ','')
        if len(ip)>2:
            temp_filter=open('temp_filter','w')
            temp_filter.write("src ip "+ip)
            temp_filter.close()
            cmd=[]
            #Try to run something like this:
            #nfdump -r /data/nfdump/nfcapd.current 'src ip   129.244.90.160' -n 0 -s as
            cmd.extend(["nfdump","-q","-R",self.source_file,'-f',"temp_filter","-o","pipe","-s","as"])
            for record in runProcess(cmd):
                if len(record)>2:
                    record_array=record.split('|')
                    record_dict=dict({"ip":ip,"duration":long(record_array[3])-long(record_array[1]),"flow":record_array[7],"packets":record_array[8],"bytes":record_array[9],"pps":record_array[10],"bps":record_array[11],"bpp":record_array[12].replace('\n','')})
                    yield record_dict
def loader(argv=sys.argv):
    """ doc is here
    """
    # parse command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.error, msg:
        print msg
        print "for help use --help"
        sys.exit(2)
    # process options
    for o, a in opts:
        if o in ("-h", "--help"):
            #print __doc__
            print "input format:'input nfdumpfile' 'output iplist'"
            sys.exit(0)
    #get_ipaddress_list(args[0],"temp")
    #remove_redundant_ip("temp",args[1])
    #get_input_per_ipaddress(args[0],args[1])
    ds=datasource(args[0])
    ds.get_normalize_base()
def runProcess(exe):
    p = subprocess.Popen(exe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while(True):
        retcode = p.poll() #returns None while subprocess is running
        line = p.stdout.readline()
        yield line
        if(retcode is not None):
            break
    return
if __name__=="__main__":
    sys.exit(loader())
