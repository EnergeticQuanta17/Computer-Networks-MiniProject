from pathlib import Path
from tkinter import Tk, Canvas, Entry, Text, Button, PhotoImage
from PIL import Image,ImageTk
import time
import pyshark
import tkinter as tk
import threading
from multiprocessing import Process
from time import sleep
from contextlib import contextmanager
import threading
import _thread

MAX_PACKETS=2
MAX_TIME_LIMITER=10

class TimeoutException(Exception):
    def __init__(self, msg=''):
        self.msg = msg

@contextmanager
def time_limit(seconds, msg=''):
    timer = threading.Timer(seconds, lambda: _thread.interrupt_main())
    timer.start()
    try:
        yield
    except KeyboardInterrupt:
        raise TimeoutException("Timed out for operation {}".format(msg))
    finally:
        # if the action ends in specified time, timer is canceled
        timer.cancel()


capture=pyshark.LiveCapture(interface='Wi-Fi',bpf_filter='tcp')

top_left='┌'
hori='─'
top_right='┐'


def relative_to_assets(path: str) -> Path:
    return (Path(__file__).parent) / Path(r"C:\Users\mpree\Desktop\build\assets\frame0") / Path(path)

req_flags=[0,0,0,0,0]
objects=[]

def store_in_list(store,string):
    store.append(string)
def add_to_list(packet,tcp_live):
    details=[]
    details.append((' '*15)+"PACKET NUMBER: "+packet.number)
    
    details.append("Time: "+(' '*21)+str(packet.sniff_time))
    
    details.append("Packet Length:"+(' '*24)+str(packet.length))
    
    details.append("Source Port: "+(' '*24)+tcp_live.get_field('tcp.srcport'))
    details.append("Destination Port: "+(' '*19)+tcp_live.get_field('tcp.dstport'))
    
    details.append("Ack. Number: "+(' '*25)+tcp_live.get_field('tcp.ack'))
    details.append("Ack. Number (raw): "+(' '*10)+tcp_live.get_field('tcp.ack_raw'))
    details.append("Sequence Number: "+(' '*17)+tcp_live.get_field('tcp.seq'))
    details.append("Sequence Number (raw): "+(' '*2)+tcp_live.get_field('tcp.seq_raw'))

    details.append("URG Flag: "+tcp_live.get_field('tcp.flags.urg'))
    details.append("ACK Flag: "+tcp_live.get_field('tcp.flags.ack'))
    details.append("PSH Flag: "+tcp_live.get_field('tcp.flags.push'))
    details.append("SYN Flag: "+tcp_live.get_field('tcp.flags.syn'))
    details.append("FIN Flag: "+tcp_live.get_field('tcp.flags.fin'))

    details.append("Source IP address: "+str(packet.ip.src))
    details.append("Destination IP address: "+str(packet.ip.dst))
    mega_details.append(details)

    if(len(mega_details)==1):
        display_objects(mega_details[0])
    print("reporting from add to list", len(mega_details))

def display_objects(details):
    objects.append(canvas.create_text(325.0,140,anchor="w",text=details[0],fill="#FFFFFF",font=("Inter", 27 * -1)))
    objects.append(canvas.create_text(325.0,170,anchor="w",text=details[14],fill="#FFFFFF",font=("Inter", 18 * -1)))
    objects.append(canvas.create_text(325.0,200,anchor="w",text=details[15],fill="#FFFFFF",font=("Inter", 18 * -1)))
    a=230
    c=28
    for i in range(a,500,c):
        objects.append(canvas.create_text(325.0,i,anchor="w",text=details[(i-a+c)//c],fill="#FFFFFF",font=("Inter", 18 * -1)))
    objects.append(canvas.create_text(475.0,455,anchor="w",text=details[12],fill="#FFFFFF",font=("Inter", 18 * -1)))
    objects.append(canvas.create_text(475.0,485,anchor="w",text=details[13],fill="#FFFFFF",font=("Inter", 18 * -1)))
    objects.append(canvas.create_text(625.0,454,anchor="w",text=details[11],fill="#FFFFFF",font=("Inter", 18 * -1)))
    
    
    

def destory_objects():
    global objects
    for i in objects:
        canvas.delete(i)
    objects=[]

def packet_sniffer():
    start=time.time()
    global mega_details
    mega_details=[]
    print("entering packetsniffer")
    r_flags=""
    for i in req_flags:
        r_flags+=str(i)
    print("Requested flags",r_flags)
    count=0
    capture=pyshark.LiveCapture(interface='Wi-Fi',bpf_filter='tcp')
    for packet in capture.sniff_continuously():
        tcp_live=packet.layers
        ind=0
        for layer in packet.layers:
            if(layer.layer_name=='tcp'):
                tcp_live=(packet.layers)[ind]
                break
            ind+=1

        all_flags=str(str(tcp_live.get_field('tcp.flags.urg'))+
                      str(tcp_live.get_field('tcp.flags.ack'))+
                      str(tcp_live.get_field('tcp.flags.push'))+
                      str(tcp_live.get_field('tcp.flags.syn'))+
                      str(tcp_live.get_field('tcp.flags.fin')))
        if(all_flags==r_flags):
            print(packet)
            add_to_list(packet,tcp_live)
            if(count==0):
                display_objects(mega_details[0])
            print("back to sniffing")
            count+=1
            if(count==MAX_PACKETS):
                break

def create_green():
    for i in range(20):
        flag_51=Image.open(relative_to_assets("red.png"))
        flag_51=flag_51.resize((30,50))
        print("jerk",flag_51)
        flag_51=ImageTk.PhotoImage(flag_51)
        flag_5_button1= Button(image=flag_51,borderwidth=0,highlightthickness=0,command=button_5,relief="flat")
        flag_5_button1.place(x=195.0,y=189.0,width=20,height=20)
mega_details=[]
def button_1():
    print("I got invoked")
    button_number=0
    mega_details=[]
    print("button",button_number,"pushed")
    button_number=2
    req_flags[button_number]=int(not(req_flags[button_number]))
    print(req_flags)
    if(req_flags[button_number]==1):
        flag_5_button.configure(bg='GREEN')
    else:
        flag_5_button.configure(bg='RED')
    

def button_2():
    button_number=1
    mega_details=[]
    print("button",button_number,"pushed")
    req_flags[button_number]=int(not(req_flags[button_number]))
    print(req_flags)
    if(req_flags[button_number]==1):
        flag_4_button.configure(bg='GREEN')
    else:
        flag_4_button.configure(bg='RED')
    

def button_3():
    button_number=2
    mega_details=[]
    print("button",button_number,"pushed")
    button_number=3
    req_flags[button_number]=int(not(req_flags[button_number]))
    print(req_flags)
    if(req_flags[button_number]==1):
        flag_3_button.configure(bg='GREEN')
    else:
        flag_3_button.configure(bg='RED')
    

def button_4():
    button_number=3
    mega_details=[]
    print("button",button_number,"pushed")
    button_number=0
    req_flags[button_number]=int(not(req_flags[button_number]))
    print(req_flags)
    if(req_flags[button_number]==1):
        flag_2_button.configure(bg='GREEN')
    else:
        flag_2_button.configure(bg='RED')


def button_5():
    button_number=4
    mega_details=[]
    print("button",button_number,"pushed")
    req_flags[button_number]=int(not(req_flags[button_number]))
    print(req_flags)
    print(req_flags[button_number])
    if(req_flags[button_number]==1):
        flag_1_button.configure(bg='GREEN')
    else:
        flag_1_button.configure(bg='RED')


packet_number=0

def go_next():
    global packet_number
    if(packet_number==MAX_PACKETS-1):
        return
    packet_number+=1
    
    destory_objects()
    display_objects(mega_details[packet_number])
    
def go_back():
    global packet_number
    if(packet_number==0):
        return
    packet_number-=1
    destory_objects()
    display_objects(mega_details[packet_number])

def submit_response():
    destory_objects()
    try:
        with time_limit(10):
            packet_sniffer()
    except:
        print("except block")
        destory_objects()
        objects.append(canvas.create_text(325.0,140,anchor="w",text="Time limit exceeded",fill="#FFFFFF",font=("Inter", 27 * -1)))



window = Tk()
print("Tkinter starting")
window.geometry("895x600")
window.configure(bg = "#FFFFFF")

canvas = Canvas(window,bg = "#FFFFFF",height = 600,width = 895,bd = 0,highlightthickness = 0,relief = "ridge")
canvas.place(x = 0, y = 0)
image_image_1 = PhotoImage(
    file=relative_to_assets("image_1.png"))

image_1 = canvas.create_image(447.1083984375,307.3586730957031,image=image_image_1)

button_image_1=Image.open(relative_to_assets("button_1.png"))
button_image_1=button_image_1.resize((154,54))
button_image_1=ImageTk.PhotoImage(button_image_1)
button_1 = Button(image=button_image_1,borderwidth=-1,highlightthickness=0,command=button_1,relief="flat")
button_1.place(x=41.0,y=175.0,width=150.33367919921875,height=50.0)

flag_5=Image.open(relative_to_assets("red.png"))
flag_5=flag_5.resize((30,50))
print(flag_5)
flag_5=ImageTk.PhotoImage(flag_5)
flag_5_button = Button(bg='RED',borderwidth=0,highlightthickness=0,command=button_1,relief="flat")
flag_5_button.place(x=195.0,y=189.0,width=20,height=20)

button_image_2=Image.open(relative_to_assets("button_2.png"))
button_image_2=button_image_2.resize((154,54))
button_image_2=ImageTk.PhotoImage(button_image_2)
button_2 = Button(image=button_image_2,bg='RED',fg='YELLOW',borderwidth=0,highlightthickness=0,command=button_2,relief="flat")
button_2.place(x=41.0,y=259.0,width=150.33367919921875,height=50.0)

flag_4=Image.open(relative_to_assets("red.png"))
flag_4=flag_4.resize((30,50))
print(flag_4)
flag_4=ImageTk.PhotoImage(flag_4)
flag_4_button = Button(bg='RED',borderwidth=0,highlightthickness=0,command=button_2,relief="flat")
flag_4_button.place(x=195.0,y=273.0,width=20,height=20)

button_image_3=Image.open(relative_to_assets("button_3.png"))
button_image_3=button_image_3.resize((154,54))
button_image_3=ImageTk.PhotoImage(button_image_3)
button_3 = Button(image=button_image_3,borderwidth=0,highlightthickness=0,command=button_3,relief="flat")
button_3.place(x=41.0,y=343.0,width=150.33367919921875,height=50.0)

flag_3=Image.open(relative_to_assets("red.png"))
flag_3=flag_3.resize((30,50))
print(flag_3)
flag_3=ImageTk.PhotoImage(flag_3)
flag_3_button = Button(bg='RED',borderwidth=0,highlightthickness=0,command=button_5,relief="flat")
flag_3_button.place(x=195.0,y=357.0,width=20,height=20)

button_image_4=Image.open(relative_to_assets("button_4.png"))
button_image_4=button_image_4.resize((154,54))
button_image_4=ImageTk.PhotoImage(button_image_4)
button_4 = Button(image=button_image_4,borderwidth=0,highlightthickness=0,command=button_4,relief="flat")
button_4.place(x=41.0,y=427.0,width=150.3353271484375,height=50.48724365234375)

flag_2=Image.open(relative_to_assets("red.png"))
flag_2=flag_2.resize((30,50))
print(flag_2)
flag_2=ImageTk.PhotoImage(flag_2)
flag_2_button = Button(bg='RED',borderwidth=0,highlightthickness=0,command=button_5,relief="flat")
flag_2_button.place(x=195.0,y=441.0,width=20,height=20)

button_image_5=Image.open(relative_to_assets("button_5.png"))
button_image_5=button_image_5.resize((154,54))
button_image_5=ImageTk.PhotoImage(button_image_5)
button_5 = Button(image=button_image_5,borderwidth=0,highlightthickness=0,command=button_5,relief="flat")
button_5.place(x=41.0,y=511.0,width=150.33367919921875,height=50.00000762939453)

flag_1=Image.open(relative_to_assets("red.png"))
flag_1=flag_1.resize((30,50))
print(flag_1)
flag_1=ImageTk.PhotoImage(flag_1)
flag_1_button = Button(bg='RED',borderwidth=0,highlightthickness=0,command=button_5,relief="flat")
flag_1_button.place(x=195.0,y=525.0,width=20,height=20)

canvas.create_text(157.0,51.0,anchor="nw",text="TCP TRAFFIC ANALYSER",fill="#FFFFFF",font=("Inter", 48 * -1))

button_image_6=Image.open(relative_to_assets("left.png"))
button_image_6=button_image_6.resize((154,54))
button_image_6=ImageTk.PhotoImage(button_image_6)
button_6 = Button(image=button_image_6,borderwidth=0,highlightthickness=0,command=go_back,relief="flat")
button_6.place(x=325.0,y=511.0,width=150.33367919921875,height=50.00000762939453)

button_image_7=Image.open(relative_to_assets("right.png"))
button_image_7=button_image_7.resize((154,54))
button_image_7=ImageTk.PhotoImage(button_image_7)
button_7 = Button(image=button_image_7,borderwidth=0,highlightthickness=0,command=go_next,relief="flat")
button_7.place(x=525.0,y=511.0,width=150.33367919921875,height=50.00000762939453)

button_image_8=Image.open(relative_to_assets("Submit.png"))
button_image_8=button_image_8.resize((154,54))
button_image_8=ImageTk.PhotoImage(button_image_8)
button_8 = Button(image=button_image_8,borderwidth=0,highlightthickness=0,command=submit_response,relief="flat")
button_8.place(x=725.0,y=511.0,width=150.33367919921875,height=50.00000762939453)



window.resizable(False, False)
window.mainloop()
