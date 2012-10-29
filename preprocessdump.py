import sys
import os
import getopt
import subprocess
import socket
import cPickle as pickle
class datasource:
    ip_list=set()
    susip_list=set()
    source_file=""
    def get_normalize_base(self):
        cmd=[]
        #Try to run something like this:
        #nfdump -r /data/nfdump/nfcapd.current  -n 0 -s as
        print "try to get normalize base:[0/6]"
        cmd.extend(["nfdump","-q","-R",self.source_file,"-n","1","-o","pipe","-s","ip/bytes"])
        for record in runProcess(cmd):
            if len(record)>2:
                record_array=record.split('|')
                record_dict=dict({"bytes":record_array[12]})
        cmd=[]
        print "try to get normalize base:[1/6]"
        cmd.extend(["nfdump","-q","-R",self.source_file,"-n","1","-o","pipe","-s","ip/packets"])
        for record in runProcess(cmd):
            if len(record)>2:
                record_array=record.split('|')
                record_dict["packets"]=record_array[11]
        cmd=[]
        print "try to get normalize base:[2/6]"
        cmd.extend(["nfdump","-q","-R",self.source_file,"-n","1","-o","pipe","-s","ip/flows"])
        for record in runProcess(cmd):
            if len(record)>2:
                record_array=record.split('|')
                record_dict["flow"]=record_array[10]
        cmd=[]
        print "try to get normalize base:[3/6]"
        cmd.extend(["nfdump","-q","-R",self.source_file,"-n","1","-o","pipe","-s","ip/bps"])
        for record in runProcess(cmd):
            if len(record)>2:
                record_array=record.split('|')
                record_dict["bps"]=record_array[14]
        cmd=[]
        print "try to get normalize base:[4/6]"
        cmd.extend(["nfdump","-q","-R",self.source_file,"-n","1","-o","pipe","-s","ip/pps"])
        for record in runProcess(cmd):
            if len(record)>2:
                record_array=record.split('|')
                record_dict["pps"]=record_array[13]
        cmd=[]
        print "try to get normalize base:[5/6]"
        cmd.extend(["nfdump","-q","-R",self.source_file,"-n","1","-o","pipe","-s","ip/bpp"])
        for record in runProcess(cmd):
            if len(record)>2:
                record_array=record.split('|')
                record_dict["bpp"]=record_array[15].replace('\n','')
        #secons in a day
        print "try to get normalize base:[6/6]"
        record_dict["duration"]=86400
        self.base=record_dict
        print record_dict
        return record_dict
    def dump_sus_to_file(self,filename):
        output=open(filename,'wb')
        dict_list=[]
        for line in self.get_sus_dict():
            dict_list.append(line)
        pickle.dump(dict_list,output)
        output.close()
    def dump_base_to_file(self,filename):
        output=open(filename+"_base",'wb')
        pickle.dump(self.base,output)
        output.close()
    def dump_non_sus_to_file(self,filename):
        output=open(filename,'wb')
        dict_list=[]
        for line in self.get_non_sus_dict(100):
            dict_list.append(line)
        pickle.dump(dict_list,output)
        output.close()
    def load_dump_from_file(self,filename):
        inputfile=open(filename,'r')
        dict_list=[]
        dict_list=pickle.load(inputfile)
        inputfile.close()
        return dict_list
    def load_base_from_file(self,filename):
        inputfile=open(filename+'_base','r')
        self.base=pickle.load(inputfile)
        inputfile.close()
        return self.base
    def __init__(self,sourcefile):
        try:
            print "try loading dump file"
            self.source_file=sourcefile
            #self.get_ipaddress_list()
            #print "init ip list created"
            #self.get_bt_user("tracker_ip_list")
            #print "sus ip list created"
        except IOError:
            print " no good loading data file"
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
        #tempString ="nfdump -R "+self.source_file + " -o fmt:%sa >> tempfile"
        #os.system(tempString)
        #print "ip list dumped to tempfile"
        #tempfile=open("tempfile",'r')
        #for line in tempfile:
        #    if line.find(".",line.find(".")+1)-line.find(".")==4:
        #        if line not in self.ip_list: # not a duplicate
        #                self.ip_list.add(line)
        #try:
        #    os.remove("tempfile")
        #except IOError:
        #    print "remove tempfile failed"
        #try to execute nfdump -R /data/nfdump/2012/10/17/20 -a -A srcip -o fmt:%sa -n 1000 -q
        cmd=[]
        cmd.extend(["nfdump","-q","-R",self.source_file,'-a','-A','srcip',"-o",'fmt:%sa','-n','1000'])
        for record in runProcess(cmd):
            if len(record)>2:
                self.ip_list.add(record.replace('\n',''))
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
    ds.get_ipaddress_list()
    print "init ip list created"
    ds.get_bt_user("tracker_ip_list")
    print "sus ip list created"
    ds.get_normalize_base()
    ds.dump_non_sus_to_file(args[1]+"_non_sus")
    ds.dump_sus_to_file(args[1]+"_sus")
    ds.dump_base_to_file(args[1])
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
