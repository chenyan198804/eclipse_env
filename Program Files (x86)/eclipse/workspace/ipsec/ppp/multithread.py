#import threading
#import thread
#import time
#
#exitFlag = 0
#
#class myThread (threading.Thread):
#    def __init__(self, threadID, name, counter):
#        self.threadID = threadID
#        self.name = name
#        self.counter = counter
#        threading.Thread.__init__(self)
#    def run(self):
#        print "Starting " + self.name
#        print_time(self.name, self.counter, 5)
#        print "Exiting " + self.name
#
#def print_time(threadName, delay, counter):
#    while counter:
#        if exitFlag:
#            thread.exit()
#        time.sleep(delay)
#        print "%s: %s" % (threadName, time.ctime(time.time()))
#        counter -= 1
#
## Create new threads
#thread1 = myThread(1, "Thread-1", 1)
#thread2 = myThread(2, "Thread-2", 2)
#
## Start new Threads
#thread1.start()
#thread2.run()
#
#while thread2.isAlive():
#    if not thread1.isAlive():
#        exitFlag = 1
#    pass
#print "Exiting Main Thread"


import threading
import time
class timer(threading.Thread): #The timer class is derived from the class threading.Thread
    def __init__(self, num, interval):
        threading.Thread.__init__(self)
        self.thread_num = num
        self.interval = interval
        self.thread_stop = False
 
    def run(self): #Overwrite run() method, put what you want the thread do here
        while not self.thread_stop:
            print 'Thread Object(%d), Time:%s/n' %(self.thread_num, time.ctime())
            time.sleep(self.interval)
    def stop(self):
        self.thread_stop = True
       
 
def test():
    thread1 = timer(1, 1)
    thread2 = timer(2, 1)
    thread1.start()
    thread2.start()
    time.sleep(10)
    thread1.stop()
    thread2.stop()
    return
 
if __name__ == '__main__':
    test()