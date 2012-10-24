import sys
import os
import getopt
import subprocess
import pynfdump
import socket
def main(argv=sys.argv):
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
    sourcefile=args[0]
    outputfile=args[1]
    outfile = open(outputfile, "w")
    tracker=open(sourcefile,"r")
    dstip=set()
    firstline=True
    for line in tracker:
        if len(line)>1:
            line=line[:line.rfind(':')]
            print "host name "+line
            try:
                tempip=socket.gethostbyname(line)
            except Exception, Err:
                print Err
            if tempip not in dstip and tempip!="127.0.0.1" and tempip!="0.0.0.0":
                if firstline:
                    outfile.write("dst ip "+tempip+"\n")
                    firstline=False
                outfile.write("or dst ip "+tempip+"\n")
                dstip.add(tempip)
if __name__=="__main__":
    sys.exit(main())
