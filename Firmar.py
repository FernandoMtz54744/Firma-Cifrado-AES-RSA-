import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter.filedialog import askopenfilename
from tkinter import messagebox
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1

dirArchivo = ""
dirPrivateKey = ""
dirArchivoFirmado = ""
dirPublicKey = ""

def getDireccionArchivo(opc):
    dir = askopenfilename()
    if(opc == "Archivo"):
        global dirArchivo
        dirArchivo = dir
    if(opc == "Private_Key"):
        global dirPrivateKey
        dirPrivateKey = dir
    if(opc == "Archivo_Firmado"):
        global dirArchivoFirmado
        dirArchivoFirmado = dir
    if(opc == "Public_Key"):
        global dirPublicKey
        dirPublicKey = dir

def firmar():
    if(dirArchivo and dirPrivateKey):
        key = RSA.import_key(open(dirPrivateKey).read()) #Carga la llave privada
        mensajeOriginal = open(dirArchivo, "r").read()
        hash = SHA1.new(mensajeOriginal.encode("UTF-8")) #Crea el digesto
        firma = pkcs1_15.new(key).sign(hash) #Crea la firma

        #Se escribe el contenido original en el nuevo archivo
        with open(dirArchivo+"_signed", "w", newline='\n', encoding="UTF-8") as signedFile:
            signedFile.write(open(dirArchivo).read()) #Escribe el contenido original
            signedFile.write("\n-----\n") #Escribe el delimitador
        
        #Se agrega la firma
        with open(dirArchivo+"_signed", "ba") as signedFile:
            signedFile.write(firma)
        messagebox.showinfo("Firmado", "Archivo firmado exitosamente")
    else:
        messagebox.showerror("Error", "Debe ingresar los archivos para firmar")

def verificarFirma():
    if(dirArchivoFirmado and dirPublicKey):
        key = RSA.import_key(open(dirPublicKey).read()) #Carga la llave publica

        #Se separa el mensaje y la firma
        originalMsg = ""
        firma = bytes()
        esMensaje = TRUE
        with open(dirArchivoFirmado, "rb") as signedFile:
            for line in signedFile:
                if("-----".encode("UTF-8") in line):
                    esMensaje = False
                    continue
                if(esMensaje):
                    originalMsg+=line.decode("UTF-8")
                else:
                    firma+=line
        originalMsg = originalMsg[:-1] #Se elimina el ultimo salto de linea
        hash = SHA1.new(originalMsg.encode("UTF-8")) #Crea el digesto

        #Se verifica el mensaje
        try:
            pkcs1_15.new(key).verify(hash, firma)
            messagebox.showinfo("Aceptado", "Las firmas coinciden")
        except (ValueError, TypeError):
            messagebox.showerror("Error", "Las firmas no coinciden")
    else:
        messagebox.showerror("Error", "Debe ingresar los archivos para verificar la firma")

#Funcion para generar la ventana
def createSignWindow(ventana):
    signWindow = Toplevel(ventana)
    signWindow.title("Practica 3 - Firma Digital")
    signWindow.geometry("726x406")
    signWindow["bg"] = "#242424"
    ventana.wm_state('iconic')

    titulo = Label(signWindow, text="Cryptography\nEquipo16\nFirma Digital", bg="#242424", font=("Arial", 16), fg="#ffffff")
    titulo.place(x=270,y=2)

    btnSalir = Button(signWindow, text='Salir', bg="#c2185b" ,command=lambda: closeWindow(signWindow, ventana), width=20)
    btnSalir.place(x=550, y=350)

    #Firmar
    labelFirma = Label(signWindow,text="Firmar archivo", bg="#26c6da", padx=10, pady=10)
    labelFirma.place(x=125,y=120)

    btnArchivoTxt = Button( signWindow,text='Cargar Archivo (.txt)', bg="#b186f1", command=lambda: getDireccionArchivo ("Archivo"), width=20)
    btnArchivoTxt.place(x=100,y=200)

    btnArchivoPem = Button(signWindow, text='Cargar Llave Privada (.pem)', bg="#6a9eda", command=lambda: getDireccionArchivo ("Private_Key"), width=20)
    btnArchivoPem.place(x=100,y=250)

    btnFirma = Button( signWindow,text='Firmar', bg="#26c6da", command=firmar, width=20)
    btnFirma.place(x=100,y=300)

    #Verificar
    labelVerificar = Label(signWindow,text="Verificar Firma:",bg="#26c6da", padx=10, pady=10)
    labelVerificar.place(x=405, y= 120)

    btnArchivoTxt = Button(signWindow,text='Cargar Archivo (.txt)', bg="#b186f1",command=lambda: getDireccionArchivo ("Archivo_Firmado"), width=20)
    btnArchivoTxt.place(x=380, y= 200)

    btnArchivoPem = Button(signWindow,text='Cargar llave (.pem)', bg="#6a9eda",command=lambda: getDireccionArchivo ("Public_Key"), width=20)
    btnArchivoPem.place(x=380, y= 250)

    btnVerificar = Button(signWindow, text='Verificar', bg="#26c6da",command=verificarFirma, width=20)
    btnVerificar.place(x=380, y= 300)

    signWindow.protocol("WM_DELETE_WINDOW", lambda: closeWindow(signWindow, ventana))
    signWindow.mainloop()


def closeWindow(window, main):
    main.deiconify()  
    window.destroy()