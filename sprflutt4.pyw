from Tkinter import *
from tkinter import ttk
#import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import tkMessageBox
from idlelib.ToolTip import *
import serial
import time
import string
import json
import csv
import os


#         Nr  Obis Unit Value Pwd Min Max Status En
WIDTH = [ 17, 20,  8,   31,   6,  18, 19, 30,    5 ]

printable = string.ascii_letters + string.digits + string.punctuation + ' '
ascii_ctld = { 0: '<NULL>', 1: '<SOH>', 2: '<STX>', 3: '<ETX>', 4: '<EOT>', 6: '<ACK>', 21: '<NAK>', 13: '<CR>', 10: '<LF>\n', 32: '<SP>'}

serhandle = None
tx_box = None
rx_box = None
tab = 0
bcc = 0
start_bcc = 0


conf = {}
CONF_VERSION = 1
def init_conf():
    global conf
    conf = { 'ver' : CONF_VERSION, 'port' : 'COM10', 'baud' : '9600', 'devad' : '', 'pwd1' : '00000000',
             'pwd2' : '00000000', 'pwd3' : '00000000', 'pwd4' : '00000000', 'lpcnt' : 8
           }


def get_conf():
    global conf    
    try:
        with open('sprflutt.conf', 'r') as jsonfile:
            conf = json.load(jsonfile)
  
        if conf['ver'] != CONF_VERSION:
            init_conf()
    except:
        init_conf()


def put_conf():
    global conf, pwd_arr

    with open('sprflutt.conf', 'w') as jsonfile:
        json.dump(conf, jsonfile)
    pwd_arr = [ '', '', mypwd2.get(), mypwd3.get(), mypwd4.get(), mypwd1.get(), myLPcnt.get(), '' ]

def convert(c):
    if c in printable:  # do not escape <SP>
        return c

    v = ascii_ctld.get(ord(c)) # escape <SP>
    if v != None:
        return v

    return r'\x{0:02x}'.format(ord(c))

def hex_escape(s):
    return ''.join(map(convert, s))

def ser_init(port, baud):
    serhandle = None
    # init the serial port
    try:
        serhandle = serial.Serial(port, baud, timeout=5)
    except:
        print 'port open error'
        #E5.insert(0, 'Wrong port')
        tkMessageBox.showerror('',"Can't open COM port, try sending break")
        pass
    return serhandle

def log_open(name):
    loghandle = open(name, 'a')
    return loghandle
    
def log_write(lh,line, dir):
    lh.write('\n')
    lh.write( time.asctime( time.localtime(time.time()) ) )
    indication = " %s-" % dir
    lh.write(indication+hex_escape(line))
    #lh.write('\n')

def log_close(lh):
    lh.close()

def upd_bcc(bcc, c):
    global start_bcc
    
    bcc ^= ord(c)
    bcc &= 255
    if c == '\x02' or c == '\x01':
        # (re-)start bcc condition
        if start_bcc == 0:
            start_bcc = 1
            bcc = 0    
    #print start_bcc, hex(ord(c)), hex(bcc)
    return bcc

def calc_bcc(str):
    bcc = 0
    s = 0
    for c in str:
        if s:
            bcc = bcc ^ ord(c)
            if c == '\x03':
                break
        if c == '\x01' or c == '\x02':
            s = 1
    return bcc    

def readln(sh, lh):
    l = sh.readline()
    if tab == 3:
        lprx_box.insert(INSERT, hex_escape(l))
        lprx_box.see(END)         
    else:    
        rx_box.insert(INSERT, hex_escape(l))
        rx_box.see(END)         
    Tk.update(window)
    log_write(lh,l,"I")
    return l

def read(sh, lh):
    global bcc
    global start_bcc
        
    l  = 0
    resp = ''
    while l != '\x03' and l != '\x06' and l != '\x15' and l != '\x04' :
        l = sh.read()
        bcc = upd_bcc(bcc, l)

        #print 'read', hex_escape(l)
        if tab == 3:
            lprx_box.insert(INSERT, hex_escape(l))
            lprx_box.see(END)             
        else:
            rx_box.insert(INSERT, hex_escape(l))
            rx_box.see(END) 
        Tk.update(window)
        log_write(lh,l,"I")
        resp += l
        
    if l == '\x03' or l == '\x04':
        l = sh.read() # get BCC
        if bcc != ord(l):
            bcc_stat = '(BCCerr: %02X != %02X)' % (ord(l), bcc) 
        else:
            bcc_stat = ''        
        start_bcc = 0
        if tab == 3:
            lprx_box.insert(INSERT, hex_escape(l)+bcc_stat+'\n')
            lprx_box.see(END)            
        else:
            rx_box.insert(INSERT, hex_escape(l)+bcc_stat+'\n')
            rx_box.see(END)
    return resp

def write(sh, lh, line):
    sh.write(line.encode('latin-1'))
    if tab == 3:
        lptx_box.insert(INSERT, hex_escape(line)+'\n')
        lptx_box.see(END)         
    else:
        tx_box.insert(INSERT, hex_escape(line)+'\n')
        tx_box.see(END)         
    
    Tk.update(window)
    log_write(lh,line,"O")    

def signon(serhandle, dev_adr, lh):
    str = dev_adr
    l = "/?"+str+"!\r\n"
    write(serhandle, lh, l)
    readln(serhandle, lh)


def get_dm(serhandle, lh):
    str=('\x06050\r\n')
    write(serhandle, lh, str)
    dm = read(serhandle, lh)
    return dm

def get_pm1(serhandle,lh):
    l = ""
    pm = []
    str=('\x06051\r\n')
    write(serhandle, lh, str)
    pm1 = read(serhandle, lh) # expect OBJ, NAK or ERRORwrite(serhandle, lh, str)

    str=('\x01P1\x02(%s)\x03' % (mypwd1.get())) # use progmode passwd1
    bcc = calc_bcc(str)
    prg = '%s%c' % (str,bcc)
    write(serhandle, lh, prg)
    pm2 = read(serhandle, lh) # expect ACK, NAK or BREAK (passwd error)
    #print pm1, pm2
    return pm2

def rd_obj(serhandle,lh,obis,pwd):
    l = ""
    pm = []

    str=('\x01R5\x02%s()(%s)\x03' % (obis,pwd))
    bcc = calc_bcc(str)
    rd = '%s%c' % (str,bcc)
    write(serhandle, lh, rd)
    pm = read(serhandle, lh) # expect OBJ, NAK or ERROR
    #print pm
    return pm

def wr_obj(serhandle,lh,obis,val,pwd):
    l = ""
    pm = []
   
    str=('\x01W5\x02%s(%s)(%s)\x03' % (obis,val,pwd))
    bcc = calc_bcc(str)
    rd = '%s%c' % (str,bcc)
    write(serhandle, lh, rd)
    pm = read(serhandle, lh) # expect OBJ, NAK or ERROR
    #print pm
    return pm

def get_dlms(serhandle,lh):
    l = ""
    hd = []
    
    str=('\x06252\r\n')
    write(serhandle, lh, str)
    hd = readln(serhandle, lh)
    hd = read(serhandle, lh)    
    return hd


def DataMode():
    logdm = log_open('sprflutt.log')
    ser = ser_init(conf['port'],conf['baud'])
    str = '1\r' # Wakeup
    write(ser, logdm, str)
    signon(ser, conf['devad'], logdm)
    res = get_dm(ser, logdm)
    ser.close()
    log_close(logdm)

def ProgMode():
    logpm = log_open('sprflutt.log')   
    ser = ser_init(conf['port'],conf['baud'])
    str = '1\r' # Wakeup
    write(ser, logpm, str)         
    signon(ser, conf['devad'], logpm)
    res = get_pm1(ser, logpm)
    res = rd_obj(ser,logpm,'C.1.1','')
    res = rd_obj(ser,logpm,'C.90.1',mypwd2.get())    
    res = rd_obj(ser,logpm,'0.9.1',mypwd2.get())
    res = rd_obj(ser,logpm,'0.9.2',mypwd2.get())

    ser.close()    
    log_close(logpm)


def DLMSMode():
    loghd = log_open('sprflutt.log')  
    ser = ser_init(conf['port'],conf['baud'])
    str = '1\r' # Wakeup
    write(ser, loghd, str)         
    signon(ser, conf['devad'], loghd)
    res = get_dlms(ser, loghd)
    ser.close()    
    log_close(loghd)

def Prog2Mode():
    E5.delete(0, END)
    E5.insert(0, 'Entering...')       
    logpm = log_open('sprflutt.log')   
    ser = ser_init(conf['port'],conf['baud'])
    str = '1\r' # Wakeup
    write(ser, logpm, str)         
    signon(ser, conf['devad'], logpm)
    res = get_pm1(ser, logpm)
    # write res to Entry
    E5.delete(0, END)
    if res == '\x06':
        E5.insert(0, 'Progmode OK')
    else:
        E5.insert(0, '***ERR***')
    ser.close()    
    log_close(logpm)

def LPProg2Mode():
    global tab
    
    tab = 3
    Prog2Mode()
    tab = 0
    
def getLP(logType):
    global tab

    tab = 3
    logpm = log_open('sprflutt.log')   
    ser = ser_init(conf['port'],conf['baud'])
    if logType == 1: # 60 minutes    
        str=('\x01R6\x02P.01(%s;%s;%s)()\x03' % (myLPstart.get(), myLPend.get(), myLPcnt.get()))
    elif logType == 70: # 30 minutes
        str=('\x01R6\x02P.70(%s;%s;%s)()\x03' % (myLPstart.get(), myLPend.get(), myLPcnt.get()))        
    elif logType == 2: # 15 minutes
        str=('\x01R6\x02P.02(%s;%s;%s)()\x03' % (myLPstart.get(), myLPend.get(), myLPcnt.get()))
    elif logType == 60: # 10 minutes
        str=('\x01R6\x02P.60(%s;%s;%s)()\x03' % (myLPstart.get(), myLPend.get(), myLPcnt.get()))         
    elif logType == 50: # 5 minutes
        str=('\x01R6\x02P.50(%s;%s;%s)()\x03' % (myLPstart.get(), myLPend.get(), myLPcnt.get()))
    bcc = calc_bcc(str)
    prg = '%s%c' % (str,bcc)
    write(ser, logpm, prg)
    
    pm = read(ser, logpm) # expect ETX, NAK or ERROR
    while pm[-1] == '\x03':
        write(ser, logpm, '\x06')        
        pm = read(ser, logpm) # expect ETX, NAK or ERROR

    #print 'End of getLP'
    tab = 0    
    ser.close()    
    log_close(logpm)
    
def b_read(event):
    global garr
       
    for i in range(len(garr)):
        for j in range(9):
            if garr[i][j] == event.widget:
                w = i
    garr[w][7].delete(0, END)
    garr[w][7].insert(0, 'Reading...')                
    logpm = log_open('sprflutt.log')   
    ser = ser_init(conf['port'],conf['baud'])
    val = rd_obj(ser, logpm, garr[w][1].get(),pwd_arr[int(garr[w][4].get())])
    #print w,hex(ord(val[0]))
    # write val to Entry
    garr[w][7].delete(0, END)
    if ord(val[0]) == 2:
        garr[w][3].delete(0, END)
        garr[w][3].insert(0, val[val.find("(")+1:val.find(")")])
        garr[w][7].insert(0, 'OK')           
    else:
        garr[w][7].insert(0, '***ERR***')
    ser.close()    
    log_close(logpm)

def b_write(event):
    global garr
    
    #print event.widget.get()
    for i in range(len(garr)):
        for j in range(9):
            if garr[i][j] == event.widget:
                w = i
    garr[w][7].delete(0, END)
    garr[w][7].insert(0, 'Writing...')                   

    logpm = log_open('sprflutt.log')   
    ser = ser_init(conf['port'],conf['baud'])
    val = wr_obj(ser, logpm, garr[w][1].get(),garr[w][3].get(),pwd_arr[int(garr[w][4].get())])
    # write val to Entry
    #print ord(val[0]), val
    garr[w][7].delete(0, END)
    if ord(val[0]) == 6:
        garr[w][7].insert(0, 'OK')
    elif ord(val[0]) == 2:
        garr[w][7].insert(0, val[val.find("(")+1:val.find(")")])
    else:
        garr[w][7].insert(0, '***ERR***')
    ser.close()    
    log_close(logpm)     
    

def AddGrid(master, height):
    global garr
    
    if os.path.isfile("objects.csv"):
        num_lines = sum(1 for line in open('objects.csv'))    
        height = num_lines - 1

        rownum = 0
        arr = [[0 for x in range(9)]for y in range(height)]
        with open("objects.csv") as f:
                reader = csv.reader(f, delimiter=';')
                for row in reader:
                    if rownum > 1:
                        colnum = 0
                        for col in row:
                            arr[rownum-1][colnum] = col
                            colnum += 1
                    rownum += 1

        garr = [[0 for x in range(9)]for y in range(height)]
        for i in range(1,height):
            for j in range(9):
                b = Entry(master, width=WIDTH[j])
                b.insert(0, str(arr[i][j]))
                b.grid(row=i, column=j)
                garr[i][j]=b
                if j == 7: b.bind("<Double-Button-1>", b_read)
                if j == 3: b.bind("<Return>", b_write)


def SendBreak():
    ser = ser_init(conf['port'],conf['baud'])
    brk = '\x01B0\x03'  # Break
    bcc = calc_bcc(brk)
    str = '%s%c' % (brk,bcc)
    ser.write(str)
    tx_box.insert(INSERT, hex_escape(str)+'\n')
    tx_box.see(END)     
    E5.delete(0, END)
    E5.insert(0, 'Break')    
    ser.close()

def w1_clear(event):
    tx_box.delete('1.0', END)


def w2_clear(event):
    rx_box.delete('1.0', END)

def w61_clear(event):
    lptx_box.delete('1.0', END)


def w71_clear(event):
    lprx_box.delete('1.0', END)    

def callback1(sv):  
    conf['port'] = mycom.get()
    put_conf()

def callback2(sv):  
    conf['baud'] = sv.get() 
    put_conf()

def callback3(sv):  
    conf['devad'] = sv.get()
    put_conf()

def callback6(sv):  
    conf['pwd2'] = sv.get()
    put_conf()

def callback7(sv):  
    conf['pwd3'] = sv.get()
    put_conf()

def callback8(sv):  
    conf['pwd4'] = sv.get()
    put_conf()     

def callback9(sv):  
    conf['pwd1'] = sv.get()
    put_conf()

def callback10(sv):  
    conf['lpcnt'] = sv.get()
    put_conf()

def onFrameConfigure(event):
    canvas.configure(scrollregion=canvas.bbox("all"), width=965, height=300)

# draw window
window = Tk()
window.title("Sprflutt")
window.geometry("1000x500")

myaddr = StringVar()
mycom  = StringVar()
mybaud = StringVar()
mystat = StringVar()
mypwd1 = StringVar()
mypwd2 = StringVar()
mypwd3 = StringVar()
mypwd4 = StringVar()
myLPstart = StringVar()
myLPend = StringVar()
myLPcnt = StringVar()

get_conf()

mycom.set(conf['port'])
mybaud.set(conf['baud'])
myaddr.set(conf['devad'])
mypwd1.set(conf['pwd1'])
mypwd2.set(conf['pwd2'])
mypwd3.set(conf['pwd3'])
mypwd4.set(conf['pwd4'])
myLPcnt.set(conf['lpcnt'])

pwd_arr = [ '', '', mypwd2.get(), mypwd3.get(), mypwd4.get(), mypwd1.get(), '' ]

lf1 = LabelFrame(window, text="Config")
lf1.pack(fill="both", expand="yes")

mycom.trace("w", lambda name, index, mode, mycom=mycom: callback1(mycom))
L1 = Label(lf1, text='Com Port')
L1.pack(side=LEFT)
E1 = Entry(lf1, textvariable=mycom, bd=5 )
E1.pack(side=LEFT)

mybaud.trace("w", lambda name, index, mode, mybaud=mybaud: callback2(mybaud))
L2 = Label(lf1, text='Baudrate')
L2.pack(side=LEFT)
E2 = Entry(lf1, textvariable=mybaud, bd=5 )
E2.pack(side=LEFT)

nb = ttk.Notebook(window)
p1 = ttk.Frame(nb)
nb.add(p1, text='1107')
p2 = ttk.Frame(nb)
nb.add(p2, text='Progmode')
p3 = ttk.Frame(nb)
nb.add(p3, text='Load Profile')
nb.pack(expand=1, fill="both")

#**** TAB: 1107 ****

lf2 = LabelFrame(p1, text="Command")
lf2.pack(fill="both", expand="yes")

cf = Frame(lf2)
cf.pack(side = TOP)

dm = Button(cf, text="Data mode", command=DataMode)
dm.pack(side=LEFT, padx=10, pady=5)

pm = Button(cf, text="Prog mode", command=ProgMode)
pm.pack(side=LEFT, padx=10)

pm = Button(cf, text="DLMS mode", command=DLMSMode)
pm.pack(side=LEFT, padx=10)

myaddr.trace("w", lambda name, index, mode, myaddr=myaddr: callback3(myaddr))
L3 = Label(cf, text='Device address')
L3.pack(side=LEFT, padx=10)
E3 = Entry(cf, textvariable=myaddr, bd=5 )
E3.pack(side=LEFT, padx=5)

brk = Button(cf, text="Send Break", command=SendBreak)
brk.pack(side=RIGHT, padx=30)

df = Frame(lf2)
df.pack(side = TOP)

sb1 = Scrollbar(df)
sb1.pack(side=RIGHT, fill=Y)
w1 = Text(df, wrap=WORD, yscrollcommand=sb1.set,width=800,height=10)
w1.bind("<Double-Button-1>", w1_clear)
tx_box = w1
w1.pack()
sb1.config(command=w1.yview)


bf = Frame(lf2)
bf.pack(side = TOP)
sb2 = Scrollbar(bf)
sb2.pack(side=RIGHT, fill=Y)
w2 = Text(bf, wrap=WORD, yscrollcommand=sb2.set,width=800,height=10)
w2.bind("<Double-Button-1>", w2_clear)
rx_box = w2
w2.pack()
sb2.config(command=w2.yview)

#**** TAB: Progmode ****

lf3 = LabelFrame(p2, text="Command")
lf3.pack(fill="both", expand="yes")

g2f = Frame(lf3)
g2f.pack(side = TOP)

p2m = Button(g2f, text="Enter progmode", command=Prog2Mode)
p2m.pack(side=LEFT, padx=10, pady=5)

brk3 = Button(g2f, text="Send Break", command=SendBreak)
brk3.pack(side=RIGHT, padx=30)

myaddr.trace("w", lambda name, index, mode, myaddr=myaddr: callback3(myaddr))
L4 = Label(g2f, text='Device address')
L4.pack(side=LEFT, padx=10)
E4 = Entry(g2f, textvariable=myaddr, bd=5 )
E4.pack(side=LEFT, padx=5)

E5 = Entry(g2f, textvariable=mystat, bd=5 )
E5.pack(side=LEFT, padx=5)
ToolTip(E5, ["Status"])

g3f = Frame(lf3)
g3f.pack(side = TOP)

L9 = Label(g3f, text='0: None')
L9.pack(side=LEFT, padx=15)
L10 = Label(g3f, text='1: MS')
L10.pack(side=LEFT, padx=15)

mypwd2.trace("w", lambda name, index, mode, mypwd2=mypwd2: callback6(mypwd2))
L5 = Label(g3f, text='2: PWD2')
L5.pack(side=LEFT, padx=5)
E6 = Entry(g3f, textvariable=mypwd2, bd=5 )
E6.pack(side=LEFT, padx=5)

mypwd3.trace("w", lambda name, index, mode, mypwd3=mypwd3: callback7(mypwd3))
L6 = Label(g3f, text='3: PWD3')
L6.pack(side=LEFT, padx=5)
E7 = Entry(g3f, textvariable=mypwd3, bd=5 )
E7.pack(side=LEFT, padx=5)

mypwd4.trace("w", lambda name, index, mode, mypwd4=mypwd4: callback8(mypwd4))
L7 = Label(g3f, text='4: PWD4')
L7.pack(side=LEFT, padx=5)
E8 = Entry(g3f, textvariable=mypwd4, bd=5 )
E8.pack(side=LEFT, padx=5)

mypwd1.trace("w", lambda name, index, mode, mypwd1=mypwd1: callback9(mypwd1))
L8 = Label(g3f, text='5: PWD1')
L8.pack(side=LEFT, padx=5)
E9 = Entry(g3f, textvariable=mypwd1, bd=5 )
E9.pack(side=LEFT, padx=5)


g4e = Frame(lf3)
g4e.pack(side = TOP)
canvas = Canvas(g4e)
g4f = Frame(canvas)
vsb = Scrollbar(g4e, orient="vertical", command=canvas.yview)
canvas.configure(yscrollcommand=vsb.set)
vsb.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand="True")
canvas.create_window((0,0), window=g4f, anchor="nw")
g4f.bind("<Configure>", lambda event, canvas=canvas: onFrameConfigure(canvas))


l1 = Label(g4f, text="Nr")
l2 = Label(g4f, text="Obis code")
l3 = Label(g4f, text="Unit")
l4 = Label(g4f, text="Value")
l5 = Label(g4f, text="Pwd")
l6 = Label(g4f, text="Min")
l7 = Label(g4f, text="Max")
l8 = Label(g4f, text="Status")
l9 = Label(g4f, text="En")

l1.grid(row=0, column=0)
l2.grid(row=0, column=1)
l3.grid(row=0, column=2)
l4.grid(row=0, column=3)
l5.grid(row=0, column=4)
l6.grid(row=0, column=5)
l7.grid(row=0, column=6)
l8.grid(row=0, column=7)
l9.grid(row=0, column=8)

AddGrid(g4f, 138)

#**** TAB: Load Profile ****

lf5 = LabelFrame(p3, text="Command")
lf5.pack(fill="both", expand="yes")

g5f = Frame(lf5)
g5f.pack(side = TOP)

p5m = Button(g5f, text="Enter progmode", command=LPProg2Mode)
p5m.pack(side=LEFT, padx=10, pady=5)

myLPcnt.trace("w", lambda name, index, mode, myLPcnt=myLPcnt:callback10(myLPcnt))
E51 = Entry(g5f, textvariable=myLPcnt, bd=5 )
E51.pack(side=LEFT, padx=5)
ToolTip(E51, ["Block size (I2Z)"])

brk5 = Button(g5f, text="Send Break", command=SendBreak)
brk5.pack(side=RIGHT, padx=30)

g6f = Frame(lf5)
g6f.pack(side = TOP)

p6p01 = Button(g6f, text="P.01", command=lambda: getLP(1))
p6p01.pack(side=LEFT, padx=10, pady=5)
ToolTip(p6p01, ["60 minutes"])

p6p02 = Button(g6f, text="P.02", command=lambda: getLP(2))
p6p02.pack(side=LEFT, padx=10, pady=5)
ToolTip(p6p02, ["15 minutes"])

p6p50 = Button(g6f, text="P.50", command=lambda: getLP(50))
p6p50.pack(side=LEFT, padx=10, pady=5)
ToolTip(p6p50, ["5 minutes"])

p6p51 = Button(g6f, text="P.60", command=lambda: getLP(60))
p6p51.pack(side=LEFT, padx=10, pady=5)
ToolTip(p6p51, ["10 minutes"])

p6p52 = Button(g6f, text="P.70", command=lambda: getLP(70))
p6p52.pack(side=LEFT, padx=10, pady=5)
ToolTip(p6p52, ["30 minutes"])

L65 = Label(g6f, text='Start')
L65.pack(side=LEFT, padx=5)
E66 = Entry(g6f, textvariable=myLPstart, bd=5 )
E66.pack(side=LEFT, padx=5)
ToolTip(E66, ["Timestamp first Logentry (ZST10/s11/12/s13)"])

L67 = Label(g6f, text='End')
L67.pack(side=LEFT, padx=5)
E68 = Entry(g6f, textvariable=myLPend, bd=5 )
E68.pack(side=LEFT, padx=5)
ToolTip(E68, ["Timestamp last Logentry (ZST10/11/12/13)"])

d6f = Frame(lf5)
d6f.pack(side = TOP)

sb61 = Scrollbar(d6f)
sb61.pack(side=RIGHT, fill=Y)
w61 = Text(d6f, wrap=WORD, yscrollcommand=sb61.set,width=800,height=10)
w61.bind("<Double-Button-1>", w61_clear)
lptx_box = w61
w61.pack()
sb61.config(command=w61.yview)

d7f = Frame(lf5)
d7f.pack(side = TOP)

sb71 = Scrollbar(d7f)
sb71.pack(side=RIGHT, fill=Y)
w71 = Text(d7f, wrap=WORD, yscrollcommand=sb71.set,width=800,height=10)
w71.bind("<Double-Button-1>", w71_clear)
lprx_box = w71
w71.pack()
sb71.config(command=w71.yview)

# end of tabs

window.mainloop()







