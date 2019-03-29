
from multiprocessing import Process, Queue
import time

class ARP_analytics():
    def __init__(self):
        self.MAC_statistics = {}
        self.listOfSuspectedMAC = []
        
    def setListOfSuspected(self,MAC):
        if MAC not in self.listOfSuspectedMAC:
            
            self.listOfSuspectedMAC.append(MAC)
            print("setListOfSuspected(self,MAC) " + str(self.listOfSuspectedMAC))
            self.alreadySuspectedMACs.put(MAC)

    def getListOfSuspectedMAC(self):
        return self.listOfSuspectedMAC

    def analyze_ARP(self,q,alreadySuspectedMACs): 
        self.alreadySuspectedMACs = alreadySuspectedMACs
        while True:
            popped = q.get() 
            if popped == 'Stop':
                break
            # print(popped)
            self.statistics(popped)
            

    def statistics(self, MAC):
        if MAC in self.MAC_statistics.keys():
            self.MAC_statistics[MAC].addShow()
            avg = self.MAC_statistics[MAC].checkFor_ARP_flooding() # This function will return the average ARP requests this mac do. OR None...
            if avg is not None:
                if avg < 1.2:
                    self.setListOfSuspected(MAC)
                    ####################################################################
                    #self.FB_mng.postSuspectedMAC(MAC)
        else:
            self.MAC_statistics[MAC] = MAC_statis()

class MAC_statis():
    def __init__(self):
        self.showsCounter = 0
        self.lastShow = time.time()

        self.statistic_list = []
        for i in range(0,100):
            self.statistic_list.append(0)
        self.listPosition = 0

    #For circular buffering 
    def getListPosition(self):
        i = self.listPosition
        self.listPosition = (self.listPosition + 1) % 100
        return int(i)

    def addShow(self):
        self.showsCounter += 1
        index = int(self.getListPosition())
        self.statistic_list[index] = (time.time() - self.lastShow)
        self.lastShow = time.time()

    def checkFor_ARP_flooding(self):
        sum = 0
        length = 0
        if self.showsCounter < 10:
            return None

        for i in self.statistic_list:
            if i == 0:
                break
            sum = sum + i
            length += 1
            
        if length == 0 :
            return None

        AVG = sum/length
        return AVG
        # print('AVG - ' + str(AVG))
        # print('sum - ' + str(sum))
        # print('length - ' + str(length))
        