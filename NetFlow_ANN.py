import preprocessdump
from pybrain.tools.shortcuts import buildNetwork
from pybrain.datasets import SupervisedDataSet,ClassificationDataSet
from pybrain.supervised.trainers import BackpropTrainer
from pybrain.structure import LinearLayer, SigmoidLayer
from pybrain.tools.customxml.networkwriter import NetworkWriter
from pybrain.tools.customxml.networkreader import NetworkReader
from pybrain.structure.modules   import SoftmaxLayer
from pybrain.utilities           import percentError
import sys
import os
import getopt
import cPickle as pickle
from cStringIO import StringIO
import math
from random import randint
#input data format record_dict=dict({"ip":ip,"duration":record_array[4],"flow":record_array[7],"packets":record_array[8],"bytes":record_array[9],"pps":record_array[10],"bps":record_array[11],"bpp":record_array[12].replace('\n','')})
class NetFlow_ANN:
    def __init__(self):
        print "start a new instance"
        self.loaded=False
        self.has_data_source=False
        try:
            self.net=NetworkReader.readFrom('pickled_ANN')
            print "ANN has been found from an ash jar"
            self.loaded=True
        except IOError:
            print "ash jar is empty, use train() to start a new ANN"
    def normalize_data(self, source, base):
        #print source
        #print "=========================="
        #print base
        return [self.normalize_f(float(source["flow"])/float(base["flow"])),self.normalize_f(float(source["packets"])/float(base["packets"])),self.normalize_f(float(source["pps"])/float(base["pps"])),self.normalize_f(float(source["bpp"])/float(base["bpp"])),self.normalize_f(float(source["bps"])/float(base["bps"]))]
        #return [float(source["flow"])/float(base["flow"]),float(source["packets"])/float(base["packets"]),float(source["pps"])/float(base["pps"]),float(source["bpp"])/float(base["bpp"]),float(source["bps"])/float(base["bps"])]
        #return [self.normalize_f(float(source["flow"])),self.normalize_f(float(source["packets"])),self.normalize_f(float(source["pps"])),self.normalize_f(float(source["bpp"])),self.normalize_f(float(source["bps"]))]
    def normalize_f(self,x):
        #return 1.7159*math.tan(math.radians(float(2/3*x)))
        #return 1.7159*math.tan(math.degrees(float(2/3*x)))
        return (math.exp(x)-math.exp(-x))/(math.exp(x)+math.exp(-x))
    def build_data_set(self,sourcefile,sus_example_count=100,non_sus_example_count=100):
        self.source_file=sourcefile
        self.data_source=preprocessdump.datasource(sourcefile)
        self.has_data_source=True
        self.normalize_base=self.data_source.load_base_from_file(sourcefile)
        #self.data_set=SupervisedDataSet(5,1)
        self.data_set=ClassificationDataSet(5,1,nb_classes=2,class_labels=['good','p2p'])
        count=0
        #for sus_example in self.data_source.get_sus_dict(sus_example_count):
        for sus_example in self.data_source.load_dump_from_file(sourcefile+"_sus"):
            self.data_set.addSample(self.normalize_data(sus_example,self.normalize_base) , 1)
            if count*100/sus_example_count%10==0:
                progress=count*100/sus_example_count
                print '\r[{0}] {1}%'.format('#'*(progress/10), progress),
            if count==sus_example_count:
                break
            count+=1
        print "\n %d suspicious examples added" % count
        count=0
        for normal_example in self.data_source.load_dump_from_file(sourcefile+"_non_sus"):
        #for normal_example in self.data_source.get_non_sus_dict(non_sus_example_count):
            self.data_set.addSample(self.normalize_data(normal_example,self.normalize_base) , 0)
            if count*100/non_sus_example_count%10==0:
                progress=count*100/non_sus_example_count
                print '\r[{0}] {1}%'.format('#'*(progress/10), progress),
            if count==non_sus_example_count:
                break
            count+=1
        print "\n %d non_suspicious examples added" % count
        print "Training data ready"
        print "Number of training patterns: ", len(self.data_set)
        print "Input and output dimensions: ", self.data_set.indim, self.data_set.outdim
        #for x in range(0,len(self.data_set)-1):
        #    print "%d sample (input, target, class):" % x
        #    print self.data_set['input'][x], self.data_set['target'][x]#, self.data_set['class'][0]
    def training(self):
        train_set,valid_set=self.data_set.splitWithProportion(0.9)
        #train_set,valid_set=example_data.splitWithProportion(0.9)
        valid_set._convertToOneOfMany()
        train_set._convertToOneOfMany()
        print train_set.calculateStatistics()
        if not self.loaded:
            #self.net=buildNetwork(6,20,1,outclass=SoftmaxLayer)
            self.net=buildNetwork(train_set.indim,train_set.outdim,recurrent=False)
            self.net.name='PieBrain'
            print "A new ANN has been created"
        trainer=BackpropTrainer(self.net,train_set,momentum=0.1, weightdecay=0.01 )
        #trainer=BackpropTrainer(self.net,self.data_set)
        trainer.trainUntilConvergence()
        #trainer.trainEpochs(500)
        print 'training is over'
        #choose a random testing instance
        ins=randint(0,len(valid_set)-1)
        print "testing instace = "+str(valid_set['input'][ins])
        print "expecting result = "+str(valid_set['target'][ins])
        print "get = "+str(self.net.activate(valid_set['input'][ins]))
    def set_datasource(self,sourcefile):
        self.data_source=sourcefile
    def classifier(self,input,count):
        #get (count) number of ips from data source
        finished=0
        result=dict()
        for example in input:
            if finished==count:
                return
            print example
            input_data=self.normalize_data(example,self.normalize_base)
            normal,sus= self.net.activate(input_data)
            likelyhood=sus-normal
            #print '{:d} / {:d}'.format(finished,count)
            print str(finished)+"/"+str(count)
            print example['ip']+":"+ str(likelyhood)
            result[example['ip']]=likelyhood
            finished+=1
        return result
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
    ANN.build_data_set(args[0],100,2000)
    ANN.training()
    NetworkWriter.writeToFile(ANN.net,'pickled_ANN')
if __name__=="__main__":
    sys.exit(loader())
