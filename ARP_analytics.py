
from multiprocessing import Process, Queue
from firebase import firebase
import time

class ARP_analytics():
    def __init__(self):
        self.MAC_statistics = {}
        self._firebase = firebase.FirebaseApplication('https://safewifi-a7dc0.firebaseio.com', None)

        self.Trusted_MACs = []
        for i in self._firebase.get('/Trusted MAC addresses', None).values():
            self.Trusted_MACs.append(i)
        print('Trusted MACs:')
        print(self.Trusted_MACs)        

    def analyze_ARP(self,q):
        while True:
            popped = q.get() 
            if popped == 'Stop':
                break
            if popped in self.Trusted_MACs:
                continue

            print(popped)
            self.statistics(popped)
            

    def statistics(self, MAC):
        if MAC in self.MAC_statistics.keys():
            self.MAC_statistics[MAC].addShow()
            self.MAC_statistics[MAC].checkFor_ARP_flooding()
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
<<<<<<< HEAD
        print(index)
        self.statistic_list[index] = (time.time() - self.lastShow)
=======

        self.statistic_list[index](time.time() - self.lastShow)
>>>>>>> 54a171adca222ae863ff0f7c18c40f90ced3d503
        self.lastShow = time.time()

    def checkFor_ARP_flooding(self):
        sum = 0
<<<<<<< HEAD
        length = 0
        if self.showsCounter < 10:
            return

        for i in self.statistic_list:
            if i == 0:
                break
            sum = sum + i
            length += 1
            
        if length == 0 :
            return
=======
        length = len(self.statistic_list)
        if self.showsCounter < 10:
            return
        if length == 0 :
            return
        elif length == 100:
            self.statistic_list = []
            return
        for i in self.statistic_list:
            sum = sum + i
>>>>>>> 54a171adca222ae863ff0f7c18c40f90ced3d503

        AVG = sum/length
        print(AVG)