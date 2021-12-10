from Crypto.PublicKey import RSA

def generarLlaves(nombre):
    key = RSA.generate(2048)
    f = open('Private_Key_'+nombre+'.pem','wb')
    f.write(key.export_key('PEM'))
    f.close()
    f = open('Public_Key_'+nombre+'.pem','wb')
    f.write(key.public_key().export_key('PEM'))
    f.close()