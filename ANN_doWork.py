import NetFlow_ANN
import preprocessdump
import sys, os, getopt
from collections import OrderedDict
def loader(argv=sys.argv):
    try:
        opts, args= getopt.getopt(sys.argv[1:],"h",["help"])
    except getopt.error, msg:
        print msg
        print "for help use --help"
        sys.exit(2)
    for o, a in opts:
        if o in ("-h","--help"):
            print "there is no damn help"
            sys.exit(0)
    #paras: processed_dumpfile limit outputfile
    ANN=NetFlow_ANN.NetFlow_ANN()
    ANN.set_datasource(preprocessdump.datasource(args[0]))
    ANN.normalize_base=ANN.data_source.load_base_from_file(args[0])
    input=ANN.data_source.load_dump_from_file(args[0]+'_sus')
    input.extend(ANN.data_source.load_dump_from_file(args[0]+'_non_sus'))
    result=ANN.classifier(input,args[1])
    result=OrderedDict(sorted(result.items(), key=lambda t: t[1]))
    outputfile=open(args[2],'w')
    for key,value in result.items():
        outputfile.write(str(key)+' : '+str(value)+'\n')
if __name__=='__main__':
    sys.exit(loader())
