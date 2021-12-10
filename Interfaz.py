import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from Crypto.PublicKey import RSA

import Firmar as firmar
import Cifrado as cifrado

def generarLlaves(nombre):
    if(nombre):
        key = RSA.generate(1024)
        f = open('Private_Key_'+nombre+'.pem','wb')
        f.write(key.export_key('PEM'))
        f.close()
        f = open('Public_Key_'+nombre+'.pem','wb')
        f.write(key.public_key().export_key('PEM'))
        f.close()
        messagebox.showinfo("Realizado", "Llaves generadas correctamente")
    else:
        messagebox.showerror("Error", "Debe ingresar un nombre de las llaves")

#Configuracion de la ventana
ventana = Tk()
ventana.title("Practica 4 - Firma Digital / Cifrado")
ventana.geometry("726x406")
ventana["bg"] = "#242424"

titulo = Label(text="Cryptography\nPractica 4 - Firma Digital / Cifrado", bg="#242424", font=("Arial", 13), fg="#ffffff")
titulo.place(x=220,y=2)

labelName = Label(text="Nombre:", bg="#242424",padx=10, pady=10, fg="#ffffff")
labelName.place(x=100, y=85)

entryLLave = Entry()
entryLLave.place(x=180,y=95)
botonGenerarLlaves = Button( text='Generar LLaves', bg="#c2185b" , command=lambda: generarLlaves(str(entryLLave.get())), width=20)
botonGenerarLlaves.place(x=380, y=90)

btnFirmar = Button( text='Firma',bg="#26c6da", width=20, padx=10, pady=10, command=lambda:firmar.createSignWindow(ventana))
btnFirmar.place(x=150, y=200)

btnCifrar = Button( text='Cifrado',bg="#26c6da", width=20, padx=10, pady=10, command=lambda: cifrado.createCipherWindow(ventana))
btnCifrar.place(x=400,y=200)

btnAmbos = Button( text='Firma y Cifrado',bg="#26c6da", width=20, padx=10, pady=10)
btnAmbos.place(x=250,y=300)

ventana.mainloop()