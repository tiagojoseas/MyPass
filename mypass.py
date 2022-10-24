import getpass, os, json, argparse, random, string
from secrets import choice
from glob import glob
import pyperclip as pc
from datetime import datetime
from prettytable import PrettyTable
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

parser = argparse.ArgumentParser(description='Description of your program')
parser.add_argument('-s','--setup', help='Setup the mps file', required=False, action='store_true')
parser.add_argument('-n','--new', help='New Entry', required=False, action='store_true')
parser.add_argument('-a','--app',help='Get Entry', metavar="", required=False)
parser.add_argument('-f','--file',help='File', metavar="", required=False)
parser.add_argument('-i','--info', help='Info', required=False, action='store_true')
parser.add_argument('-l','--list', help='List all apps', required=False, action='store_true')
parser.add_argument('-p','--password', help='Password', metavar="", required=False)
args = parser.parse_args()

def main():
    if args.setup:
        setup()
    else:
        file = args.file
        if args.file == None:
            files = glob("./*.mps")
            len_files = len(files) 
            if len_files== 1:
                file = files[0]
            elif len_files == 0:
                print("Error: mps file not found!")
            else:
                table = PrettyTable(["No.", "MPS File"])
                counter = 0
                for f in files:
                    counter += 1
                    table.add_row([counter, f])
                print(table)
                numb = input("Choose the number of the mps file: ")
                file = files[int(numb)-1]


        password = args.password 
        if  password == None:
            password = getpass.getpass()
        if args.new:
            new(nameFile=file, app=args.app, password=password)
        if args.app:
            get(nameFile=file, app=args.app, password=password
            )
        if args.list:
            list(nameFile=file, password=password)
        if args.info:
            info(nameFile=file, password=password)

def setup():
    # Inputs
    name = input("Your Name: ")
    password = getPassword(prompt=None, random=False)

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

def dec(nameFile, password):
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
        return salt, nonce, data
    except:
        print("> Error")
        quit()

def new(nameFile, app, password):
    salt, nonce, data  = dec(nameFile=nameFile, password=password)

    if app == None: app = input("App: ")   
    email = input("Email/Username: ")   
    appPassword = getPassword(prompt="App Password (Enter to generate randomly): ", random=True)

    ENTRYS = data["entrys"]   
    APP = {app:{"email": email, "password": appPassword}}

    if(ENTRYS == None):
        data["entrys"] = {}

    data["entrys"].update(APP)

    save(nonce=nonce, salt=salt, data=data, password=password, nameFile=nameFile)   

def get(nameFile, app, password):
    salt, nonce, data  = dec(nameFile=nameFile, password=password)
    table = PrettyTable(["No.","App", "Email/User", "Password"])
    ENTRYS = data["entrys"]
    counter = 0
    for entry in ENTRYS:
        if app in entry:
            APP = ENTRYS[entry]
            counter += 1
            table.add_row([counter, entry, APP["email"], "- copied to clipboard -"])

    print(table)
    pc.copy(APP["password"])

def list(nameFile, password):
    salt, nonce, data  = dec(nameFile=nameFile, password=password)
    
    table = PrettyTable(["No.", "App", "Email/User"])
    ENTRYS = data["entrys"]
    counter = 0
    for entry in ENTRYS:
        counter+=1
        row = [counter, entry, ENTRYS[entry]["email"]]
        table.add_row(row)
    
    print(table)

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

def info(nameFile, password):
    salt, nonce, data  = dec(nameFile=nameFile, password=password)
    table = PrettyTable(["Data", "Info"])
    table.add_row(["User", data["user"]])
    table.add_row(["Creation Data", data["creation_date"]])
    table.add_row(["Number of Entrys", str(len(data["entrys"]))])
    table.add_row(["Last Update", data["last_update"]])
    print(table)

def getPassword(prompt, random):
    if prompt:
        password = getpass.getpass(prompt)
        if random and not password:
            print("- copied to clipboard -")
            return ''.join(random.choice(string.printable) for i in range(32))
    else:    
        password = getpass.getpass()
    auxPassword = getpass.getpass("Verificar a Password: ")

    if password != auxPassword:
        print("ERRO: Passwords não coincidem")
        quit()
    
    return password
    
if __name__ == "__main__":
    main()