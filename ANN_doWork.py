import NetFlow_ANN
import preprocessdump
import sys, os, getopt
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
    ANN=NetFlow_ANN.NetFlow_ANN()
    ANN.net.sortModules()
    ANN.set_datasource(preprocessdump.datasource(args[0]))
    ANN.normalize_base=ANN.data_source.load_base_from_file(args[0])
    print "p2p test"
    ANN.random_p2p_test(args[0],limit=1,Verbose=True)
    print "non p2p test"
    ANN.random_non_p2p_test(args[0],limit=1,Verbose=True)
if __name__=='__main__':
    sys.exit(loader())
