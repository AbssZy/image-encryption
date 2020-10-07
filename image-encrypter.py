# Image Encryptor
# MADE in Python 2.7.15

#Libraies used

from Tkinter import *
from tkFileDialog import *
import tkMessageBox
import os
from  PIL import Image 
import PIL
import math
from Crypto.Cipher import AES
import hashlib
import binascii
import base64

global password # make pass global var

# encryption method
# -----------------
def encrypt(imagename,password):
    # initialize variables
    plaintext = list()
    plaintextstr = ""
    
    # loading  the image
    im = Image.open(imagename)  # open target image which will be encrypted
    pix = im.load()
    
    #print im.size   # print size of image (width,height)
    width = im.size[0]
    height = im.size[1]
    
    # break up the image into a list, each with pixel values and then append to a string
    for y in range(0,height):
        #print("Row: %d") %y  # print row number
        for x in range(0,width):
            #print pix[x,y]  # print each pixel RGB tuple
            plaintext.append(pix[x,y])
            
    # add 100 to each tuple value to make sure each are 3 digits long.  being able to do this is really just a PoCfor i in range(0,len(plaintext)):
    for i in range(0,len(plaintext)):
        for j in range(0,3):
            plaintextstr = plaintextstr + "%d" %(int(plaintext[i][j])+100)
            
    
    # length save for encrypted image reconstruction
    relength = len(plaintext)
    
    # append dimensions of image for reconstruction after decryption
    plaintextstr += "h" + str(height) + "h" + "w" + str(width) + "w"
    
    # make sure that plantextstr length is a multiple of 16 for AES.  if not, append "n".  not safe in theory
    # and i should probably replace this with an initialization vector IV = 16 * '\x00' at some point.  In practice
    # this IV buffer should be random.
    while (len(plaintextstr) % 16 != 0):
        plaintextstr = plaintextstr + "n"
    
    # encrypt plaintext
    obj1 = AES.new(password, AES.MODE_CBC, 'This is an IV456')
    ciphertext = obj1.encrypt(plaintextstr)
    
    # write ciphertext to file for analysis
    cipher_name = imagename + ".crypt"
    g = open(cipher_name, 'w')
    base64_ciphertext = base64.b64encode(ciphertext)
    g.write(base64_ciphertext)
    

    
# decryption method
# -----------------
def decrypt(ciphername,password):
    
    # reach ciphertext into memory
    cipher = open(ciphername,'r')
    ciphertext = cipher.read()
    denc=base64.b64decode(ciphertext)
    
    # decrypt ciphertext with password
    obj2 = AES.new(password, AES.MODE_CBC, 'This is an IV456')
    decrypted = obj2.decrypt(denc)
    
    # parse the decrypted text back into integer string
    decrypted = decrypted.replace("n","")
    
    # extract dimensions of images
    newwidth = decrypted.split("w")[1]
    newheight = decrypted.split("h")[1]
    
    # replace height and width with emptyspace in decrypted plaintext
    heightr = "h" + str(newheight) + "h"
    widthr = "w" + str(newwidth) + "w"
    decrypted = decrypted.replace(heightr,"")
    decrypted = decrypted.replace(widthr,"")

    # reconstruct the list of RGB tuples from the decrypted plaintext
    step = 3
    finaltextone=[decrypted[i:i+step] for i in range(0, len(decrypted), step)]
    finaltexttwo=[(int(finaltextone[int(i)])-100,int(finaltextone[int(i+1)])-100,int(finaltextone[int(i+2)])-100) for i in range(0, len(finaltextone), step)]    

    # reconstruct image from list of pixel RGB tuples
    newim = Image.new("RGB", (int(newwidth), int(newheight)))
    newim.putdata(finaltexttwo)
    newim.show()
    
# ---------------------
# GUI CODE
# ---------------------

# empty password box alert
def pass_alert():
    tkMessageBox.showinfo("Password Alert","Please enter a Valid password.")
    
def enc_success(imagename):
    tkMessageBox.showinfo("Successful","Encrypted Image: " + imagename) 
    
# image encrypt button event
def image_open():
    # useless for now, may need later
    global file_path_e
    
    # check to see if password entry is null.  if yes, alert
    enc_pass = passg.get()
    if enc_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(enc_pass).digest()
        filename = askopenfilename()
        file_path_e = os.path.dirname(filename)
        # encrypt the image
        encrypt(filename,password)
    
# image decrypt button event
def cipher_open():
    # useless for now, may need later
    global file_path_d
    # check to see if password entry is null.  if yes, alert
    dec_pass = passg.get()
    if dec_pass == "":
        pass_alert()
    else:    
        password = hashlib.sha256(dec_pass).digest()
        filename = askopenfilename()
        file_path_d = os.path.dirname(filename)
        # decrypt the ciphertext
        decrypt(filename,password)

# main gui app starts here
class App:
    def __init__(self, master):
    # make passg global to use in functions
    global passg
    # setup frontend titles
    title ="Image Security System"
    author = "Made By: AbssZy"
    msgtitle = Message(master, text =title)
    msgtitle.config(font=("Times", "24", "bold italic"), width=500)
    msgauthor = Message(master, text=author)
    msgauthor.config(font=("helvetica","15","bold"), width=200)

    # draw canvas
    canvas_width = 350
    canvas_height = 100
    w = Canvas(master,width=canvas_width,height=canvas_height)

    # pack the GUI, this is basic, we shold use a grid system
    msgtitle.pack()
    msgauthor.pack()
    w.pack()
    
    # password field here above buttons
    passlabel = Label(master, text="Enter Encryption/Decryption Password:",font=25)
    passlabel.pack()
    passg = Entry(master, show="*", width=45)
    passg.pack()

    # add both encrypt/decrypt buttons here which trigger file browsers
    self.encrypt = Button(master,text="Encrypt",fg="black",font=30,command=image_open, width=20,height=5)
    self.encrypt.pack(side=LEFT)
    self.decrypt = Button(master,text="Decrypt", fg="black",font=30,command=cipher_open, width=20,height=5)
    self.decrypt.pack(side=RIGHT)



root = Tk()
root.wm_title("Image Security System")
app = App(root)
root.mainloop()

#THANKYOU
#REGARDS AbssZy