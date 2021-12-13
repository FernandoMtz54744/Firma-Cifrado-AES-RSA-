import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter.filedialog import askopenfilename
from tkinter import messagebox
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

from Cifrado import cifrar

dirArchivo = ""
dirPrivateKey = ""
dirArchivoRecibido = ""
dirPublicKey = ""

def getDireccionArchivo(opc):
    dir = askopenfilename()
    if(opc == "Archivo"):
        global dirArchivo
        dirArchivo = dir
    if(opc == "Private_Key"):
        global dirPrivateKey
        dirPrivateKey = dir
    if(opc == "Archivo_Recibido"):
        global dirArchivoRecibido
        dirArchivoRecibido = dir
    if(opc == "Public_Key"):
        global dirPublicKey
        dirPublicKey = dir

def cifrar():
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
    datosCifrado = {"iv": iv, "keyAesCifrada": keyAESCipher, "textoCifrado": ciphertext}
    return datosCifrado

def descifrar():
    archivoCifradoContent = open(dirArchivoRecibido, "rb").read() #Se obtiene el contenido del archivo recibido
    iv = archivoCifradoContent[0:16] #Se obtiene el vector de inicializacion (16 bytes)
    mensajeCifrado = archivoCifradoContent[16:archivoCifradoContent.find("-----".encode("UTF-8"))]
    keyAESCifrado = archivoCifradoContent[archivoCifradoContent.find("-----".encode("UTF-8"))+5:archivoCifradoContent.find("#####".encode("UTF-8"))]
    #Se descifra la llave AES usando RSA
    privateKey = RSA.import_key(open(dirPrivateKey).read()) #Se carga la llave privada
    cipherRSA = PKCS1_OAEP.new(privateKey)
    keyAES = cipherRSA.decrypt(keyAESCifrado)
    #Se decrifa el mensaje usando AES
    cipherAES = AES.new(keyAES, AES.MODE_CBC, iv=iv)
    mensaje = cipherAES.decrypt(mensajeCifrado)
    mensaje = mensaje.decode("UTF-8")
    return mensaje

def firmar():
    key = RSA.import_key(open(dirPrivateKey).read()) #Carga la llave privada
    mensajeOriginal = open(dirArchivo, "r").read()
    hash = SHA1.new(mensajeOriginal.encode("UTF-8")) #Crea el digesto
    firma = pkcs1_15.new(key).sign(hash) #Crea la firma
    return firma

def verificar(mensaje):
    key = RSA.import_key(open(dirPublicKey).read()) #Carga la llave publica
    #Se obtiene la firma del archivo
    archivoContent = open(dirArchivoRecibido, "rb").read()
    firma = archivoContent[archivoContent.find("#####".encode("UTF-8"))+5:]
    #Se aplica el hash al mensaje descifrado
    hash = SHA1.new(mensaje.encode("UTF-8")) #Crea el digesto
    #Se verifica el mensaje
    firmaValida = FALSE
    try:
        pkcs1_15.new(key).verify(hash, firma)
        firmaValida = TRUE
    except (ValueError, TypeError):
        print("No coinciden")
    return firmaValida

def cifrarFirmar():
    if(dirArchivo and dirPrivateKey and dirPublicKey):
        datosCifrado = cifrar()
        firma = firmar()
        with open(dirArchivo.replace(".txt","_CF.txt"), "wb") as archivoDestino:
            archivoDestino.write(datosCifrado["iv"]) #Se escribe el vector de inicializacion
            archivoDestino.write(datosCifrado["textoCifrado"]) #Se escribe el texto cifrado
            archivoDestino.write("-----".encode("UTF-8")) #Se escribe el delimitador del texto
            archivoDestino.write(datosCifrado["keyAesCifrada"]) #Se escribe la llave AES cifrada
            archivoDestino.write("#####".encode("UTF-8")) #Se escribe el delimitador de la llave
            archivoDestino.write(firma) #Se agrega la firma
        messagebox.showinfo("Realizado", "Se ha Cifrado y Firmado el documento")
    else:
        messagebox.showerror("Error", "Debe ingresar todos los archivos necesarios\n(Archivo, Llave Privada y Publica)")


def descifrarVerificar():
    if(dirArchivoRecibido and dirPrivateKey and dirPublicKey):
        mensaje = descifrar()
        firmaValida = verificar(mensaje)
        with open(dirArchivoRecibido.replace(".txt","_DV.txt"), "w") as archivoDestino:
            archivoDestino.write(mensaje) #Se escribe el mensaje descrifrado
        messagebox.showinfo("Valida", "El archivo ha sido descifrado")
        if(firmaValida):
            messagebox.showinfo("Valida", "La firma coincide")
        else:
            messagebox.showerror("Erro", "La firma no coincide")
    else:
        messagebox.showerror("Error", "Debe ingresar todos los archivos necesarios\n(Archivo recibido, Llave Privada y Publica)")

#Funcion para generar la ventana
def createBothWindow(ventana):
    bothWindow = Toplevel(ventana)
    bothWindow.title("Practica 3 - Firma Digital")
    bothWindow.geometry("726x406")
    bothWindow["bg"] = "#242424"
    ventana.wm_state('iconic')

    titulo = Label(bothWindow, text="Cryptography\nEquipo16\nFirma/Cifrado", bg="#242424", font=("Arial", 16), fg="#ffffff")
    titulo.place(x=270,y=2)

    btnSalir = Button(bothWindow, text='Salir', bg="#c2185b" ,command=lambda: closeWindow(bothWindow, ventana), width=20)
    btnSalir.place(x=550, y=350)

    #Cifrar y Firmar
    labelCF = Label(bothWindow,text="Cifrar y Firmar", bg="#26c6da", padx=10, pady=10)
    labelCF.place(x=125,y=100)

    btnArchivoTxt = Button( bothWindow,text='Cargar Archivo (.txt)', bg="#b186f1", command=lambda: getDireccionArchivo ("Archivo"), width=20)
    btnArchivoTxt.place(x=100,y=170)

    btnCF = Button( bothWindow,text='Cifrar y Firmar', bg="#26c6da", command=cifrarFirmar, width=20)
    btnCF.place(x=100,y=320)

    #Verificar
    labelDV = Label(bothWindow,text="Descrifrar y Verificar",bg="#26c6da", padx=10, pady=10)
    labelDV.place(x=405, y= 100)

    btnArchivoTxt = Button(bothWindow,text='Cargar Archivo Recibido(.txt)', bg="#b186f1",command=lambda: getDireccionArchivo ("Archivo_Recibido"), width=20)
    btnArchivoTxt.place(x=380, y= 170)

    btnDV = Button(bothWindow, text='Descifrar y Verificar', bg="#26c6da",command=descifrarVerificar, width=20)
    btnDV.place(x=380, y= 320)

    #Llaves
    btnArchivoPemPri = Button(bothWindow, text='Cargar Llave Privada (.pem)', bg="#6a9eda", command=lambda: getDireccionArchivo ("Private_Key"), width=20)
    btnArchivoPemPri.place(x=250,y=230)

    btnArchivoPemPu = Button(bothWindow,text='Cargar llave publica(.pem)', bg="#6a9eda",command=lambda: getDireccionArchivo ("Public_Key"), width=20)
    btnArchivoPemPu.place(x=250, y= 280)

    bothWindow.protocol("WM_DELETE_WINDOW", lambda: closeWindow(bothWindow, ventana))
    bothWindow.mainloop()


def closeWindow(window, main):
    main.deiconify()  
    window.destroy()