import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter.filedialog import askopenfilename
from tkinter import messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

dirArchivo = ""
dirPublicKey = ""
dirArchivoCifrado = ""
dirPrivateKey = ""

def getDireccionArchivo(opc):
    dir = askopenfilename()
    if(opc == "Archivo"):
        global dirArchivo
        dirArchivo = dir
    if(opc == "Public_Key"):
        global dirPublicKey
        dirPublicKey = dir
    if(opc == "Archivo_Cifrado"):
        global dirArchivoCifrado
        dirArchivoCifrado = dir
    if(opc == "Private_Key"):
        global dirPrivateKey
        dirPrivateKey = dir

def cifrar():
    if(dirArchivo and dirPublicKey):
        archivoData = open(dirArchivo).read() #Se lee el archivo
        keyAES =  get_random_bytes(16) #Se genera la llave de AES
        #Se cifra en AES modo CBC
        cipherAES = AES.new(keyAES, AES.MODE_CBC)
        iv = cipherAES.iv #Vector de inicializacion
        ciphertext = cipherAES.encrypt(archivoData.encode("UTF-8"))

        #Se cifra la llave de AES con RSA
        publicKey = RSA.import_key(open(dirPublicKey).read())
        cipherRSA = PKCS1_OAEP.new(publicKey)
        keyAESCipher = cipherRSA.encrypt(keyAES)

        #Se crea el archivo cifrado
        with open(dirArchivo+"_Cifrado", "wb") as archivoCifrado:
            archivoCifrado.write(iv) #Se escribe el vector de inicializacion
            archivoCifrado.write(ciphertext) #Se escribe el texto cifrado
            archivoCifrado.write("-----".encode("UTF-8")) #Se escribe delimitador del mensaje
            archivoCifrado.write(keyAESCipher) #Se escribe la llave AES cifrada 
        messagebox.showinfo("Cifrado", "El archivo ha sido cifrado")

        print(iv)
    else:
        messagebox.showerror("Error", "Debe ingresar los archivos para cifrar")

    

def descifrar():    
    if(dirArchivoCifrado and dirPrivateKey):
        archivoCifradoContent = open(dirArchivoCifrado, "rb").read() #Se obtiene el contenido del archivo cifrado
        iv = archivoCifradoContent[0:16] #Se obtiene el vector de inicializacion (16 bytes)
        mensajeCifrado = archivoCifradoContent[16:archivoCifradoContent.find("-----".encode("UTF-8"))]
        keyAESCifrado = archivoCifradoContent[archivoCifradoContent.find("-----".encode("UTF-8"))+5:]
        
        #Se descifra la llave AES usando RSA
        privateKey = RSA.import_key(open(dirPrivateKey).read()) #Se carga la llave privada
        cipherRSA = PKCS1_OAEP.new(privateKey)
        keyAES = cipherRSA.decrypt(keyAESCifrado)

        #Se decrifa el mensaje usando AES
        cipherAES = AES.new(keyAES, AES.MODE_CBC, iv=iv)
        mensaje = cipherAES.decrypt(mensajeCifrado)
        mensaje = mensaje.decode("UTF-8")

        with open(dirArchivoCifrado+"_Descifrado", "w") as archivoOriginal:
            archivoOriginal.write(mensaje)

        messagebox.showinfo("Descifrado", "El archivo ha sido descrifrado")
    else:
        messagebox.showerror("Error", "Debe ingresar los archivos para descifrar")

def createCipherWindow(ventana):
    CipherWindow = Toplevel(ventana)
    CipherWindow.title("Practica 3 - Cifrado")
    CipherWindow.geometry("726x406")
    CipherWindow["bg"] = "#242424"
    ventana.wm_state('iconic')

    titulo = Label(CipherWindow, text="Cryptography\nEquipo16\nCifrado", bg="#242424", font=("Arial", 16), fg="#ffffff")
    titulo.place(x=270,y=2)

    btnSalir = Button(CipherWindow, text='Salir', bg="#c2185b" ,command=lambda: closeWindow(CipherWindow, ventana), width=20)
    btnSalir.place(x=550, y=350)

    #Cifrar
    labelCifrar= Label(CipherWindow,text="Cifrar archivo", bg="#26c6da", padx=10, pady=10)
    labelCifrar.place(x=125,y=120)

    btnArchivoTxt = Button( CipherWindow,text='Cargar Archivo (.txt)', bg="#b186f1", command=lambda: getDireccionArchivo ("Archivo"), width=20)
    btnArchivoTxt.place(x=100,y=200)

    btnArchivoPem = Button(CipherWindow, text='Cargar Llave Publica Receptor (.pem)', bg="#6a9eda", command=lambda: getDireccionArchivo ("Public_Key"), width=20)
    btnArchivoPem.place(x=100,y=250)

    btnCifrar = Button( CipherWindow,text='Cifrar', bg="#26c6da", command=cifrar, width=20)
    btnCifrar.place(x=100,y=300)

    #Descifrar
    labelDescifrar = Label(CipherWindow,text="Descifrar Archivo:",bg="#26c6da", padx=10, pady=10)
    labelDescifrar.place(x=405, y= 120)

    btnArchivoTxt2 = Button(CipherWindow,text='Cargar Archivo Cifrado (.txt)', bg="#b186f1",command=lambda: getDireccionArchivo ("Archivo_Cifrado"), width=20)
    btnArchivoTxt2.place(x=380, y= 200)

    btnArchivoPem2 = Button(CipherWindow,text='Cargar llave Privada (.pem)', bg="#6a9eda",command=lambda: getDireccionArchivo ("Private_Key"), width=20)
    btnArchivoPem2.place(x=380, y= 250)

    btnDescifrar = Button(CipherWindow, text='Descifrar', bg="#26c6da",command=descifrar, width=20)
    btnDescifrar.place(x=380, y= 300)

    CipherWindow.protocol("WM_DELETE_WINDOW", lambda: closeWindow(CipherWindow, ventana))
    CipherWindow.mainloop()


def closeWindow(window, main):
    main.deiconify()  
    window.destroy()