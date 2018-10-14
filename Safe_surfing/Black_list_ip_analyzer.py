from multiprocessing import Process, Queue
from firebase import firebase

class blackListAnalyze():
    def __init__(self,queue):
        self.q = queue
        self.blackList = TheBlackList()
        self._firebase = firebase.FirebaseApplication('https://safewifi-a7dc0.firebaseio.com', None)

    def analyze_IP(self,q): 
        while True:
            popped = q.get() 
            if popped == 'Stop':
                break
            try:
                host_name , alias, addresslist = socket.gethostbyaddr(ip)
                host_ip = socket.gethostbyname(host_name) 
                print("Hostname :  ",host_name) 
                print("IP : ",host_ip)
            except:
                pass

    def get_black_list_IPs(self):
        self.blackList.Chatting = self._firebase.get('/Black_List_Web_Site/Chatting',None)
        self.blackList.Porn = self._firebase.get('/Black_List_Web_Site/Porn',None)
        self.blackList.Gambling = self._firebase.get('/Black_List_Web_Site/Gambling',None)

class TheBlackList():
    def __init__(self):
        self.Gambling = []
        self.Porn = []
        self.Chatting = []
