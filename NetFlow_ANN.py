import preprocessdump
from pybrain.tools.shortcuts import buildNetwork
from pybrain.datasets import SupervisedDataSet,ClassificationDataSet
from pybrain.supervised.trainers import BackpropTrainer
from pybrain.structure import LinearLayer, SigmoidLayer
from pybrain.tools.customxml.networkwriter import NetworkWriter
from pybrain.tools.customxml.networkreader import NetworkReader
import sys
import os
import getopt
import cPickle as pickle
from cStringIO import StringIO

#input data format record_dict=dict({"ip":ip,"duration":record_array[4],"flow":record_array[7],"packets":record_array[8],"bytes":record_array[9],"pps":record_array[10],"bps":record_array[11],"bpp":record_array[12].replace('\n','')})
class NetFlow_ANN:
    def __init__(self):
        #self.net=buildNetwork(7,7,1)
        try:
            self.net=NetworkReader.readFrom('pickled_ANN')
            print "ANN has been found from an ash jar"
        except IOError:
            self.net=buildNetwork(7,7,1)
            self.net.name='PieBrain'
            print "A new ANN has been created"
    def normalize_data(self, source, base):
        #print source
        #print "=========================="
        #print base
        return [float(source["duration"])/float(base["duration"]),float(source["flow"])/float(base["flow"]),float(source["packets"])/float(base["packets"]),float(source["bytes"])/float(base["bytes"]),float(source["pps"])/float(base["pps"]),float(source["bpp"])/float(base["bpp"]),float(source["bps"])/float(base["bps"])]
    def build_data_set(self,sourcefile,sus_example_count=100,non_sus_example_count=100):
        self.source_file=sourcefile
        self.data_source=preprocessdump.datasource(sourcefile)
        self.normalize_base=self.data_source.load_base_from_file(sourcefile)
        self.data_set=SupervisedDataSet(7,1)
        count=0
        first=True
        #for sus_example in self.data_source.get_sus_dict(sus_example_count):
        for sus_example in self.data_source.load_dump_from_file(sourcefile+"_non_sus"):
            self.data_set.appendLinked(self.normalize_data(sus_example,self.normalize_base) , [1])
            if first:
                print "data example="+str(sus_example)
                first=False
            if count*100/sus_example_count%10==0:
                progress=count*100/sus_example_count
                print '\r[{0}] {1}%'.format('#'*(progress/10), progress),
            count+=1
        print "\n %d suspicious examples added" % count
        count=0
        for normal_example in self.data_source.load_dump_from_file(sourcefile+"_sus"):
        #for normal_example in self.data_source.get_non_sus_dict(non_sus_example_count):
            self.data_set.appendLinked(self.normalize_data(normal_example,self.normalize_base) , [0])
            if count*100/non_sus_example_count%10==0:
                progress=count*100/non_sus_example_count
                print '\r[{0}] {1}%'.format('#'*(progress/10), progress),
            count+=1
        print "\n %d non_suspicious examples added" % count
        print "Training data ready"
    def training(self):
        #trainer=BackpropTrainer(self.net,self.data_set,verbose=True)
        trainer=BackpropTrainer(self.net,self.data_set)
        trainer.trainUntilConvergence()
        #trainer.trainEpochs(10000)
    def set_datasource(self,sourcefile):
        self.data_source=sourcefile
    def random_non_p2p_test(self,sourcefile,limit=10):
        for normal_example in self.data_source.load_dump_from_file(sourcefile+"_sus"):
            validation_input=self.normalize_data(normal_example,self.normalize_base)
            result=self.net.activate(validation_input)
            print result
        print "validation over"
    def random_p2p_test(self,sourcefile,limit=10):
        for sus_example in self.data_source.load_dump_from_file(sourcefile+"_sus"):
            validation_input=self.normalize_data(sus_example,self.normalize_base)
            result=self.net.activate(validation_input)
            print result
        print "validation over"
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
    ANN=NetFlow_ANN()
    ANN.build_data_set(args[0],100,50)
    ANN.training()
    #print "valid non p2p"
    #ANN.random_non_p2p_test()
    #print "valid p2p"
    #ANN.random_p2p_test()
    NetworkWriter.writeToFile(ANN.net,'pickled_ANN')
if __name__=="__main__":
    sys.exit(loader())
