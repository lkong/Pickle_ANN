import sys
import os
import getopt
import subprocess
import socket
import cPickle as pickle


def get_normalize_base(self):
    cmd=[]
    #Try to run something like this:
    #nfdump -r /data/nfdump/nfcapd.current  -n 0 -s as
    cmd.extend(["nfdump","-q","-R",self.source_file,"-n","1","-o","pipe","-s","as"])
    for record in runProcess(cmd):
        if len(record)>2:
            record_array=record.split('|')
            record_dict=dict({"duration":long(record_array[3])-long(record_array[1]),"flow":record_array[7],"packets":record_array[8],"bytes":record_array[9],"pps":record_array[10],"bps":record_array[11],"bpp":record_array[12].replace('\n','')})
            self.base=record_dict
            return record_dict
