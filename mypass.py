import json
import sys, getpass, os
import pyperclip as pc
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def main(args = sys.argv):
    command = args[1]
    if command == "setup":
        setup()
    if command == "new":
       new(nameFile=args[2])
    if command == "get":
       get(nameFile=args[2], app=args[3])
    if command == "info":
       info(nameFile=args[2])
    if command == "loop":
       loop(nameFile=args[2])

def loop(nameFile):
    None


def setup():
    # Inputs
    name = input("Your Name: ")
    password = getPassword()

    nameFile = name.replace(" ", "").lower() + ".mps"

    info = {
        "user": name,
        "creation_date": str(datetime.now()),
        "last_update": "",
        "entrys": {}
    }

    salt = os.urandom(16)
    nonce = os.urandom(12)

    save(nonce=nonce, salt=salt, data=info, password=password, nameFile=nameFile)   
    print("> Nome do seu ficheiro: "+ nameFile)

def PBKDF(salt):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )    

def dec(nameFile):

    password = getpass.getpass()
    bytePassword = password.encode()

    f = open(nameFile, "rb")
    file = f.read()
    f.close()
    
    salt = file[:16]
    nonce = file[16:28]
    ct = file[28:]

    key = PBKDF(salt).derive(bytePassword)

    try:
        PBKDF(salt).verify(bytePassword, key)
        chacha = ChaCha20Poly1305(key)
        dt = chacha.decrypt(nonce, ct, None)
        data = json.loads(dt.decode())  
        return salt, nonce, data, password
    except:
        print("> Error")
        quit()

def new(nameFile):
    salt, nonce, data, password  = dec(nameFile=nameFile)

    app = input("App: ")   
    email = input("Email/Username: ")   
    appPassword = getPassword("App Password: ")

    ENTRYS = data["entrys"]   
    APP = {app:{"email": email, "password": appPassword}}

    if(ENTRYS == None):
        data["entrys"] = {}

    data["entrys"].update(APP)

    save(nonce=nonce, salt=salt, data=data, password=password, nameFile=nameFile)   

def get(nameFile, app):
    salt, nonce, data, password  = dec(nameFile=nameFile)
    ENTRYS = data["entrys"]
    APP = ENTRYS[app]
    print("\nEmail    :"+APP["email"])
    print("Password : - copied to clipboard - ")
    pc.copy(APP["password"])


def save(nonce, salt, data, password, nameFile):
    #Create Key    
    key = PBKDF(salt).derive(password.encode())
    chacha = ChaCha20Poly1305(key)

    data["last_update"] = str(datetime.now())
    
    #Encript Data
    ct = chacha.encrypt(nonce,json.dumps(data).encode(),None)
    file = open(nameFile, "wb")
    file.write(salt)
    file.write(nonce)
    file.write(ct)
    file.close()

def info(nameFile):
    salt, nonce, data, password  = dec(nameFile=nameFile)
    print("User             :"+ data["user"])
    print("Creation Data    :"+ data["creation_date"])
    print("Number of Entrys :"+ str(len(data["entrys"])))
    print("Last Update      :"+ data["last_update"])

def getPassword(prompt):
    password = getpass.getpass(prompt)
    auxPassword = getpass.getpass("Verificar a Password: ")

    if password != auxPassword:
        print("ERRO: Passwords não coincidem")
        quit()
    
    return password
    
if __name__ == "__main__":
    main()