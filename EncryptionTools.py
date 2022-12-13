import codecs
import msvcrt
from time import sleep
import uuid
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64, pickle, json
import zipfile
import os
import pyperclip
import blosc
import typing
import chardet
import configparser
import winsound
import random

# https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal
# http://jafrog.com/2013/11/23/colors-in-terminal.html
class bcolors:

    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    PURPLE = "\033[0;34m"
    PINK = "\033[0;35m"
    CYAN = "\033[0;36m"
    GRAY = "\033[0;37m"

    LIGHT_BLACK = "\033[90m"
    LIGHT_RED = "\033[91m"
    LIGHT_GREEN = "\033[92m"
    LIGHT_YELLOW = "\033[93m"
    LIGHT_PURPLE = "\033[94m"
    LIGHT_PINK = "\033[95m"
    LIGHT_CYAN = "\033[96m"
    LIGHT_GRAY = "\033[97m"

    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"

# for code in range(30,38):
#     print( "\033[%sm \\033[%sm \033[0m"%(code,code), end=" ")
#     print( "\033[%s;1m \\033[%s;1m \033[0m"%(code,code), end=" ")
#     print( "\033[%s;3m \\033[%s;3m \033[0m"%(code,code), end=" ")
#     print( "\033[%s;4m \\033[%s;4m \033[0m"%(code,code), end=" ")
#     print( "\033[%sm \\033[%sm \033[0m"%(code+60,code+60))
# print(f"{bcolors.GREEN}Hello{bcolors.BOLD}{bcolors.UNDERLINE} World{bcolors.END}")

def color_print(s, mode):
    if mode=="GOK":
        print(f"{bcolors.GREEN}{s}{bcolors.END}")
    elif mode=="BOK":
        print(f"{bcolors.CYAN}{s}{bcolors.END}")
    elif mode=="FAIL":
        print(f"{bcolors.UNDERLINE}{bcolors.BOLD}{bcolors.RED}{s}{bcolors.END}")
    elif mode=="WARNING":
        print(f"{bcolors.UNDERLINE}{bcolors.BOLD}{bcolors.YELLOW}{s}{bcolors.END}")

def AES_Encrypt(password: str, data: bytes, comment: str = "") -> bytes:
    try:
        
        # generate password
        salt = os.urandom(16)
        iv = os.urandom(16)
        kdf = PBKDF2HMAC(hashes.SHA512(), 32, salt, ITERATION, backend=default_backend())
        password = kdf.derive(password.encode())

        # pad data
        padder = PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()

        # encrypt
        cipher = Cipher(algorithms.AES(password), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypt_data = encryptor.update(data) + encryptor.finalize()

        dump={
            "comment": base64.b64encode(bytes(comment, encoding="utf-8")).decode("ascii"),
            "bytes": base64.b64encode(salt + encrypt_data + iv).decode("ascii"),
        }
        
        dump = base64.b64encode(bytes(json.dumps(dump), encoding="ascii"))

        return dump
    except:
        return False

def getComment(encrypt_data):
    try:
        if type(encrypt_data)==bytes:
            return base64.b64decode(json.loads(base64.b64decode(encrypt_data.decode("ascii")).decode("ascii"))["comment"]).decode("utf-8")
        elif type(encrypt_data)==str:
            return base64.b64decode(json.loads(base64.b64decode(encrypt_data).decode("ascii"))["comment"]).decode("utf-8")
        else:
            return ""
    except:
        return ""

def AES_Decrypt(password: str, encrypt_data):
    try:
        # re-generate password from
        if type(encrypt_data)==bytes:
            try:
                encrypted_obj = base64.b64decode(json.loads(base64.b64decode(encrypt_data.decode("ascii")).decode("ascii"))["bytes"])
            except Exception as e:
                color_print(e, "FAIL")
                print("Trying old method...")
                encrypted_obj=base64.b64decode(encrypt_data)
        
        elif type(encrypt_data)==str:
            encrypted_obj = base64.b64decode(json.loads(base64.b64decode(encrypt_data).decode("ascii"))["bytes"])
        
        salt = encrypted_obj[0:16]
        iv = encrypted_obj[-16:]
        ciphertext = encrypted_obj[16:-16]
        kdf = PBKDF2HMAC(hashes.SHA512(), 32, salt, ITERATION, backend=default_backend())
        password = kdf.derive(password.encode())

        # decrypt
        cipher = Cipher(algorithms.AES(password), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_text = decryptor.update(ciphertext) + decryptor.finalize()

        # remove padding
        unpadder = PKCS7(128).unpadder()
        decrypt_data = unpadder.update(padded_text) + unpadder.finalize()
        
        try:
            decrypt_data=pickle.loads(decrypt_data)
        except:
            pass

        return decrypt_data
    except:
        return False

def Base64_Encode(thing, encoding_for_str="utf-8") -> str:
    if type(thing)==bytes:
        res=base64.b64encode(thing).decode("ascii")
    elif type(thing)==str:
        res=base64.b64encode(bytes(thing, encoding_for_str)).decode("ascii")
    else:
        res=base64.b64encode(pickle.dumps(thing)).decode("ascii")

    if WIDTH!=-1:
        return "\n".join([ res[i:i+WIDTH] for i in range(0, len(res), WIDTH)])
    else:
        return res

def Base64_Decode(base64_s: str, TYPE: typing.Union[str,bytes,object], encoding_for_str="utf-8"):
    try:
        res=base64.b64decode(base64_s.strip().replace("\n","").encode("ascii"))
    except:
        return False
    if TYPE==bytes:
        return res
    elif TYPE==str:
        try:
            return res.decode(encoding_for_str)
        except:
            return False
    elif TYPE==object:
        return pickle.loads(res)
    else:
        return res

def Base64_Encode_Save(thing, file_path, encoding_for_str="utf-8"):
    with open(file_path, "w") as f:
        f.write(Base64_Encode(thing, encoding_for_str))

def Base64_Decode_Load(file_path, TYPE: typing.Union[str,bytes,object], encoding_for_str="utf-8"):
    with open(file_path, "r") as f:
        res=Base64_Decode(f.read(), TYPE, encoding_for_str)
    return res

def Compress_Save(data: bytes, file_path):
    if not os.path.exists(os.path.dirname(os.path.abspath(file_path))):
        os.makedirs(os.path.dirname(file_path))
        
    with open(file_path,"wb") as f:
        f.write(blosc.compress(data, cname="zlib"))

def Decompress_Load(file_path):
    with open(file_path,"rb") as f:
        data=blosc.decompress(f.read())
    
    return data

def Leet_Encode(raw_text, standard):
    with open("leet.dll", "rb") as f:
        leet_dict=pickle.loads(blosc.decompress(f.read()))[0]

    leet_text=""
    for i in raw_text:
        i=i.lower()
        if leet_dict.get(i)!=None:
            if standard:
                leet_text+=leet_dict[i][0]
            else:
                leet_text+=leet_dict[i][random.randint(0,len(leet_dict[i])-1)]
        else:
            leet_text+=i
    
    return leet_text

def Leet_Decode(leet_text):
    with open("leet.dll", "rb") as f:
        leet_reverse_dict=pickle.loads(blosc.decompress(f.read()))[1]

    raw_text=""
    for i in leet_text:
        found=False
        for j in leet_reverse_dict:
            if i in j:
                raw_text+=leet_reverse_dict[j]
                found=True
                break
        if not found:
            raw_text+=i
    
    return raw_text

def fix_path(file_path: str):
    file_path=file_path.strip()
    if file_path:
        if file_path[0]=="\"" and file_path[-1]=="\"":
            file_path=file_path[1:-1]
        
        elif file_path[0]=="\'" and file_path[-1]=="\'":
            file_path=file_path[1:-1]

        file_path=file_path.strip("\\")

    return file_path

def lazy_input(prompt=""):
    print(prompt, end="")
    while True:
        try:
            res = input()
            break
        except:
            return False
    return res

def zip_files(zip_file_path, file_paths):

    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as myzip:
        for fp in file_paths:
            if os.path.isdir(fp):
                for root, dirs, files in os.walk(fp):
                    for file in files:
                        myzip.write(
                            os.path.join(root, file),
                            os.path.relpath(os.path.join(root, file),os.path.join(fp, '..'))
                        )
                    
                    empty_dirs = [dir for dir in dirs if os.listdir(os.path.join(root, dir)) == []]
                    for dir in empty_dirs:  
                        myzip.write(
                            os.path.join(root, dir) + "/", 
                            os.path.relpath(os.path.join(root, dir),os.path.join(fp, '..'))
                        )
                    
            elif os.path.isfile(fp):
                myzip.write(
                    fp,
                    os.path.basename(fp)
                )

def unzip_file(zip_file_path, dst_path):
    
    safe=True
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            for member in zip_file.infolist():
                file_path=os.path.join(dst_path, member.filename)
                if os.path.exists(file_path):
                    color_print("%s already exsit"%file_path, "FAIL")
                    safe=False

            if safe:
                zip_file.extractall(dst_path)
                return safe
            else:
                pass
        
        color_print("ZIP file will be retained at %s. Process terminated..."%zip_file_path, "WARNING")
        return safe
    except Exception as e:
        raise e

def open_explorer_file(file_path):
    if OPEN_EXPLOER:
        os.popen("explorer /select,\"%s\""%file_path)

def open_explorer_dir(file_path):
    if OPEN_EXPLOER:
        os.popen("explorer \"%s\""%file_path)

def flush_input():
    # https://stackoverflow.com/questions/65976696/how-to-ignore-input-while-in-a-loop-python
    while msvcrt.kbhit():
        msvcrt.getch()

def slow_print(s):
    stop_words = ["，","。","！","？","；","：","、"]
    for c in s:
        flush_input()
        print(c, end="", flush=True)
        while True:
            try:
                if c in stop_words:
                    sleep(DELAY_STOP)
                else:
                    sleep(DELAY_NORMAL)
            except:
                continue
            break
    print()

def input_multiple_lines(placeholder, text_list=None) -> str:
    sentinel = ""
    print(placeholder)
    print("-"*50)
    text=[]
    if not text_list:
        while True:
            c = lazy_input()
            if c!=False:
                if c == sentinel:
                    break
                else:
                    text.append(c)
            else:
                return False
        print("-"*50)
        print()
    else:
        for c in text_list:
            if c == sentinel:
                break
            else:
                text.append(c)
       
    if text:
        text = "\n".join(text)
    else:
        text = ""
    
    return text

def input_multiple_files(file_paths=None):
    print("Input file path (end with a new line with Ctrl+D):")
    print("-"*50)
    sentinel = ""
    
    if not file_paths:
        file_paths=[]
        while True:
            c = lazy_input()
            if c!=False:
                if c == sentinel:
                    break
                else:
                    c=fix_path(c)
                    if c.strip():
                        if os.path.exists(c):
                            if c not in file_paths:
                                file_paths.append(c)
                                color_print("%s added"%c, "GOK")
                            else:
                                color_print("%s will be ignored since it's already in list!"%c, "WARNING")
                        else:
                            color_print("%s will be ignored since it does not exist!"%c, "WARNING")
            else:
                file_paths=[]
                break
    else:
        input_file_path=file_paths
        file_paths=[]
        for c in input_file_path:
            c=fix_path(c)
            if c.strip():
                if os.path.exists(c):
                    if c not in file_paths:
                        file_paths.append(c)
                        color_print("%s added"%c, "GOK")
                    else:
                        color_print("%s will be ignored since it's already in list!"%c, "WARNING")
                else:
                    color_print("%s will be ignored since it does not exist!"%c, "WARNING")
    print("-"*50)
    print()

    return file_paths

def flush_console(title):
    os.system("cls")
    print(f"{bcolors.LIGHT_PINK}{bcolors.ITALIC}{'%-78s'%title}{bcolors.LIGHT_BLACK}Version {VERSION}{bcolors.END}{bcolors.END}\n")

def get_zipped_bytes(file_paths):
    zip_file_path= os.path.join(os.path.dirname(file_paths[0]), str(uuid.uuid4())+".zip")
    zip_files(zip_file_path, file_paths)
    
    try:
        with open(zip_file_path, "rb") as f:
            files_bytes=f.read()
    except Exception as e:
        color_print(e, "FAIL")
        os.remove(zip_file_path)
        lazy_input()
        return
    
    os.remove(zip_file_path)

    return files_bytes

def try_unpack_zip(file_bytes, file_path, operation_text):
    try:
        zip_file_path= os.path.join(os.path.dirname(file_path), str(uuid.uuid4())+".zip")
        with open(zip_file_path, "wb") as f:
            f.write(file_bytes)
        if unzip_file(zip_file_path, os.path.dirname(file_path)):
            os.remove(zip_file_path)
            color_print("The %s file is saved to %s!\n"%(operation_text, file_path), "BOK")
        open_explorer_dir(os.path.dirname(file_path))
        lazy_input("Press Enter to go back...")
        return
    except Exception as e:
        color_print(e, "FAIL")
    
    os.remove(zip_file_path)
    color_print("File cannot decode as zip, it will be saved to a pickle file", "WARNING")
    if os.path.exists(file_path+".pickle"):
        color_print("%s already exsits!"%file_path, "FAIL")
        n,e = os.path.splitext(file_path)
        n = n+str(uuid.uuid4())
        file_path = n+e
    file_path = file_path+".pickle"
    with open(file_path, "wb") as f:
        pickle.dump(file_bytes, f)
    open_explorer_file(file_path)
    lazy_input("File saved to %s\n"%file_path)

def decrypt_with_taunting(current_password, encrypted_bytes):
    try_times=0
    WRONG=False
    while True:
        try_times+=1
        index=try_times-len(taunts_and_responses)
        if WRONG:
            if index<0:
                print("Try again (or Press Ctrl+C to quit)")
                current_password=input_multiple_lines("Input password (end with a new line with Ctrl+D):")
            elif index<len(taunts_and_responses):
                slow_print(taunts_and_responses[index][0]) # taunt
                print("%s attempts left!"%(len(taunts_and_responses)-index))
                current_password=input_multiple_lines("Input password (end with a new line with Ctrl+D):")
            else:
                color_print(李田所, "FAIL") # taunt
                getLoud()
                lazy_input()
                break

        if current_password!=False:
            decrypted = AES_Decrypt(current_password, encrypted_bytes)
            if decrypted is not False:
                return decrypted
            else:
                WRONG=True
                color_print("Wrong Password!!!", "FAIL")
                if index>=0:
                    slow_print(taunts_and_responses[index][1]) # responses
                    print()
                continue
        else:
            break
    
    return False

def getLoud():
    with open('yjsnpi.dll',"rb") as f:
        data=pickle.load(f)

    i=random.randint(0,len(data)-1)
    winsound.PlaySound(blosc.decompress(data[i]), winsound.SND_MEMORY)

def EncryptString(input_text: list = None, password: list = None, comment: list = None):
    
    flush_console("Mode: Encrypt String")
    input_text=input_multiple_lines("Input raw string (end with a new line with Ctrl+D):", input_text)

    if input_text!=False:
        
        flush_console("Mode: Encrypt String")
        password=input_multiple_lines("Input password (end with a new line with Ctrl+D):", password)
        
        if password!=False:
            
            flush_console("Mode: Encrypt String")
            comment=input_multiple_lines("Input comment (end with a new line with Ctrl+D):", comment)
            
            if comment!=False:
                flush_console("Mode: Encrypt String")
                print("Encrypting...")
                
                string_encrypt=AES_Encrypt(password, bytes(input_text, encoding="utf-8"), comment).decode("ascii")
                if WIDTH!=-1:
                    string_encrypt = "\n".join([ string_encrypt[i:i+WIDTH] for i in range(0, len(string_encrypt), WIDTH)])
                color_print("Encryption Successed!", "GOK")
                pyperclip.copy(string_encrypt)
                color_print("The encrypted string is in your clipboard!\n", "BOK")
                lazy_input("Press Enter to go back...")

def DecryptString(input_text: str = None, password: list = None):

    flush_console("Mode: Decrypt String")
    input_text=input_multiple_lines("Input encrypted string (end with a new line with Ctrl+D):", input_text)
    if input_text!=False:
        try:
            packed_bytes = input_text.encode("ascii")
        except Exception as e:
            flush_console("Mode: Decrypt String")
            color_print(e, "FAIL")
            lazy_input()
            return
    else:
        return
    
    comment=getComment(packed_bytes)
    
    flush_console("Mode: Decrypt String")
    print("Comment:")
    print("-"*50)
    print(comment)
    print("-"*50)
    
    current_password=input_multiple_lines("Input password (end with a new line with Ctrl+D):", password)
    
    string_decrypted=decrypt_with_taunting(current_password, packed_bytes)
    if string_decrypted!=False:
        string_decrypted=string_decrypted.decode("utf-8")
        flush_console("Mode: Decrypt String")
        color_print("Decryption Successed!","GOK")
        print("-"*50)
        print(string_decrypted)
        print("-"*50)
        pyperclip.copy(string_decrypted)
        color_print("The decrypted string is in your clipboard!\n", "BOK")
        lazy_input("Press Enter to go back...")
            
def EncryptFile(file_paths: list = None, password: list = None, comment: list = None):
    
    flush_console("Mode: Encrypt File")
    file_paths = input_multiple_files(file_paths)

    if file_paths:
        
        flush_console("Mode: Encrypt File")
        password=input_multiple_lines("Input password (end with a new line with Ctrl+D):", password)
        
        if password!=False:
            flush_console("Mode: Encrypt File")
            print("Making zip file...")
            files_bytes=get_zipped_bytes(file_paths)

            flush_console("Mode: Encrypt File")
            comment=input_multiple_lines("Input comment (end with a new line with Ctrl+D):", comment)
            
            if comment!=False:
                flush_console("Mode: Encrypt File")
                print("Encrypting...")
                
                encrypted_bytes = AES_Encrypt(password, files_bytes, comment)
                dst_file_path = file_paths[0]+".encrypt"
                
                with open(dst_file_path,"wb") as f:
                    f.write(blosc.compress(encrypted_bytes, cname="zlib"))

                color_print("Encryption Successed!", "GOK")
                open_explorer_file(dst_file_path)
                color_print("The encrypted file is saved to %s!\n"%dst_file_path, "BOK")
                lazy_input("Press Enter to go back...")

def DecryptFile(file_path: str = None, password: list = None):

    flush_console("Mode: Decrypt File")

    if not file_path:
        file_path=lazy_input("Input encrypted file path: ")
        if file_path!=False:
            file_path=fix_path(file_path)
        else:
            return
    
    print("Opening encrypted file...")
    with open(file_path,"rb") as f:
        packed_bytes=blosc.decompress(f.read())

    comment=getComment(packed_bytes)

    flush_console("Mode: Decrypt File")
    print("Comment:")
    print("-"*50)
    print(comment)
    print("-"*50)
    
    current_password=input_multiple_lines("Input password (end with a new line with Ctrl+D):", password)
    
    file_decrypted = decrypt_with_taunting(current_password, packed_bytes)
    if file_decrypted:
        flush_console("Mode: Decrypt File")
        color_print("Decryption Successed!", "GOK")
        file_path = file_path.replace(".encrypt","")
        try_unpack_zip(file_decrypted, file_path, "decrypted")

def Base64EncodeString(input_text: list = None, encoding: str = None):
    
    flush_console("Mode: Base64 Encode String")
    input_text=input_multiple_lines("Input raw string (end with a new line with Ctrl+D):", input_text)

    if input_text!=False:
        
        while True:

            if not encoding:
                encoding = lazy_input("Encoding Codec (default to utf-8): ")
            
            if encoding!=False:
                encoding = encoding.strip()
                if not encoding:
                    encoding="utf-8"
                
                try:
                    string_encode = codecs.lookup(encoding).encode(input_text)[0]
                    print("Encoding with %s"%encoding)
                    string_encode = Base64_Encode(string_encode)
                    pyperclip.copy(string_encode)
                    color_print("The Base64 Encoded string is in your clipboard!\n", "BOK")
                    lazy_input("Press Enter to go back...")
                    break
                except Exception as e:
                    encoding=False
                    color_print(e, "FAIL")
                    lazy_input("")
            else:
                break

def Base64DecodeString(input_text: list = None, encoding: str = None):
    
    flush_console("Mode: Base64 Decode String")
    input_text=input_multiple_lines("Input Base64 Encoded string (end with a new line with Ctrl+D):", input_text)

    if input_text!=False:
        string_B_decode = Base64_Decode(input_text, bytes)
        if string_B_decode==False:
            color_print("Decoding Error!", "FAIL")
            lazy_input()
            return

        det=chardet.detect_all(string_B_decode)
        while True:
            flush_console("Mode: Base64 Decode String")
            print("Codec Detection:")
            index=0
            for i in det:
                if index==0:
                    print("\t", bcolors.LIGHT_GREEN, "%-12s"%i["encoding"], "Confidence:", "%.2f"%i["confidence"], "Language:", i["language"], "\t<-- default", bcolors.END)
                else:
                    print("\t", "%-12s"%i["encoding"], "Confidence:", "%.2f"%i["confidence"], "Language:", i["language"])
                index+=1
            
            if not encoding:
                encoding = lazy_input("Decoding Codec: ")
            
            if encoding!=False:
                encoding = encoding.strip()
                if not encoding:
                    encoding=det[0]["encoding"]
                
                try:
                    string_decode = codecs.lookup(encoding).decode(string_B_decode)[0]
                    print("Decoding with %s"%encoding)
                    print("-"*50)
                    print(string_decode)
                    print("-"*50)
                    pyperclip.copy(string_decode)
                    color_print("The Base64 Decoded string is in your clipboard!\n", "BOK")
                    lazy_input("Press Enter to go back...")
                    break
                except Exception as e:
                    color_print(e, "FAIL")
                    encoding=False
                    lazy_input("")
            else:
                break

def Base64EncodeFile(file_paths: list = None):
    
    flush_console("Mode: Base64 Encode File")
    file_paths = input_multiple_files(file_paths)

    if file_paths:

        flush_console("Mode: Base64 Encode File")
        print("Making zip file...")
        files_bytes=get_zipped_bytes(file_paths)
        
        dst_file_path = file_paths[0]+".encode"
        Base64_Encode_Save(files_bytes, dst_file_path)
        color_print("Encoding Successed!", "GOK")
        open_explorer_file(dst_file_path)
        color_print("The Base64 Encoded file is saved to %s!\n"%dst_file_path, "BOK")
        lazy_input("Press Enter to go back...")

def Base64DecodeFile(file_path: str = None):
    
    flush_console("Mode: Base64 Decode File")
    if not file_path:
        file_path=lazy_input("Input Base64 Encoded file path: ")
        if file_path:
            file_path=fix_path(file_path)
        else:
            return

    try:
        file_bytes=Base64_Decode_Load(file_path, bytes)
        if not file_bytes:
            color_print("Decoding Error!", "FAIL")
            lazy_input()
            return
    except Exception as e:
        color_print(e, "FAIL")
        lazy_input()
        return
    
    flush_console("Mode: Base64 Decode File")
    color_print("Decoding Successed!", "GOK")
    file_path = file_path.replace(".encode","")
    try_unpack_zip(file_bytes, file_path, "decoded")

def CompressFile(file_paths: list = None):
    
    flush_console("Mode: Compress File")
    file_paths = input_multiple_files(file_paths)

    if file_paths:
        
        flush_console("Mode: Compress File")
        print("Making zip file...")
        files_bytes=get_zipped_bytes(file_paths)
        
        dst_file_path = file_paths[0]+".compress"
        Compress_Save(files_bytes, dst_file_path)
        color_print("Compress Successed!", "GOK")
        open_explorer_file(dst_file_path)
        color_print("The compressed file is saved to %s!\n"%dst_file_path, "BOK")
        lazy_input("Press Enter to go back...")

def DecompressFile(file_path: str = None):
    
    flush_console("Mode: Decompress File")
    if not file_path:
        file_path=lazy_input("Input compressed file path: ")
        if file_path:
            file_path=fix_path(file_path)
        else:
            return
    
    try:
        file_bytes=Decompress_Load(file_path)
    except Exception as e:
        color_print(e, "FAIL")
        lazy_input()
        return
    
    flush_console("Mode: Decompress File")
    file_path = file_path.replace(".compress","")
    try_unpack_zip(file_bytes, file_path, "decompressed")

def LeetEncodeString(input_text: list = None, standard: bool = None):
    flush_console("Mode: Leet Encode String")
    input_text=input_multiple_lines("Input raw string (end with a new line with Ctrl+D):", input_text)

    if input_text!=False:
        if standard==None:
            flush_console("Mode: Leet Encode String")
            standard = lazy_input("Standard Leet? Y/N: ")

            if standard!=False:
                if standard.lower()=="y":
                    standard=True
                else:
                    standard=False
            else:
                return
        
        flush_console("Mode: Leet Encode String")
        if standard:
            print("Using standard leet...")
        else:
            print("Using random leet...")
        
        string_encode = Leet_Encode(input_text, standard)
        pyperclip.copy(string_encode)
        color_print("The Leet string is in your clipboard!\n", "BOK")
        lazy_input("Press Enter to go back...")

def LeetDecodeString(input_text: list = None):
    
    flush_console("Mode: Leet Decode String")
    input_text=input_multiple_lines("Input Leet string (end with a new line with Ctrl+D):", input_text)

    if input_text!=False:
        string_decode = Leet_Decode(input_text)
        flush_console("Mode: Leet Decode String")
        print("-"*50)
        print(string_decode)
        print("-"*50)
        pyperclip.copy(string_decode)
        color_print("The Leet Decoded string is in your clipboard!\n", "BOK")
        lazy_input("Press Enter to go back...")

def EditConfig():
    os.startfile("UserSetting.ini")
    while True:
        flush_console("Editing Config (Press Enter to reload Config):")
        load_config()
        print(f"""\
        {bcolors.LIGHT_YELLOW}WIDTH: {bcolors.END}{bcolors.LIGHT_GREEN}{bcolors.UNDERLINE}{WIDTH}{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> Output Width in Encrypt String \ Base64 Encode String{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> Set -1 to disable line splitting{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> Default to 32{bcolors.END}
        
        {bcolors.LIGHT_YELLOW}DELAY_NORMAL: {bcolors.END}{bcolors.LIGHT_GREEN}{bcolors.UNDERLINE}{DELAY_NORMAL}{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> Normal Words' Delay in decrypt_with_taunting{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> Default to 0.07{bcolors.END}
        
        {bcolors.LIGHT_YELLOW}DELAY_STOP: {bcolors.END}{bcolors.LIGHT_GREEN}{bcolors.UNDERLINE}{DELAY_STOP}{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> Stopwords' Delay in decrypt_with_taunting{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> Default to 0.56{bcolors.END}
        
        {bcolors.LIGHT_YELLOW}ITERATION: {bcolors.END}{bcolors.LIGHT_GREEN}{bcolors.UNDERLINE}{ITERATION}{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> Iteration of key generation in Encrypt \ Decrypt{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> {bcolors.BOLD}Decryption error with wrong password could be caused by inconsistent iteration{bcolors.END}
        {bcolors.ITALIC}{bcolors.LIGHT_BLACK}> Default to 48000{bcolors.END}


                                        {bcolors.RED}{bcolors.BOLD}{bcolors.ITALIC}Back: Ctrl+C{bcolors.END}
""")
        if lazy_input("                                        ")==False:
            break

def Console():
    while True:
        os.system("cls")
        flush_console("Select Mode:")
        mode = print(f"""\
        {bcolors.LIGHT_GREEN}01.{bcolors.END} {bcolors.UNDERLINE}Encrypt String{bcolors.END}           {bcolors.LIGHT_GREEN}05.{bcolors.END} {bcolors.UNDERLINE}Base64 Encode String{bcolors.END}             {bcolors.LIGHT_GREEN}09.{bcolors.END} {bcolors.UNDERLINE}Compress File{bcolors.END}
        {bcolors.LIGHT_GREEN}02.{bcolors.END} {bcolors.UNDERLINE}Decrypt String{bcolors.END}           {bcolors.LIGHT_GREEN}06.{bcolors.END} {bcolors.UNDERLINE}Base64 Decode String{bcolors.END}             {bcolors.LIGHT_GREEN}10.{bcolors.END} {bcolors.UNDERLINE}Decompress File{bcolors.END}
        {bcolors.LIGHT_GREEN}03.{bcolors.END} {bcolors.UNDERLINE}Encrypt File{bcolors.END}             {bcolors.LIGHT_GREEN}07.{bcolors.END} {bcolors.UNDERLINE}Base64 Encode File{bcolors.END}               {bcolors.LIGHT_GREEN}11.{bcolors.END} {bcolors.UNDERLINE}Leet Encode String{bcolors.END}
        {bcolors.LIGHT_GREEN}04.{bcolors.END} {bcolors.UNDERLINE}Decrypt File{bcolors.END}             {bcolors.LIGHT_GREEN}08.{bcolors.END} {bcolors.UNDERLINE}Base64 Decode File{bcolors.END}               {bcolors.LIGHT_GREEN}12.{bcolors.END} {bcolors.UNDERLINE}Leet Decode String{bcolors.END}
""")
        print(f"                                        {bcolors.PURPLE}{bcolors.BOLD}{bcolors.ITALIC}9961. Edit Config{bcolors.END}\n")
        print(f"                                        {bcolors.RED}{bcolors.BOLD}{bcolors.ITALIC}Exit: Ctrl+C{bcolors.END}\n")
        
        mode = lazy_input("                                        ")
        if mode==False:
            break

        try:
            mode=int(mode)
        except:
            continue
        
        if mode == 1:
            EncryptString()
        elif mode == 2:
            DecryptString()
        elif mode == 3:
            EncryptFile()
        elif mode == 4:
            DecryptFile()
        elif mode == 5:
            Base64EncodeString()
        elif mode == 6:
            Base64DecodeString()
        elif mode == 7:
            Base64EncodeFile()
        elif mode == 8:
            Base64DecodeFile()
        elif mode == 9:
            CompressFile()
        elif mode == 10:
            DecompressFile()
        elif mode == 11:
            LeetEncodeString()
        elif mode == 12:
            LeetDecodeString()
        elif mode == 9961:
            EditConfig()
        else:
            continue

def Command(args):
    
    mode=args.mode
    func=mode_dict[mode]
    inputs=args.inputs
    comment=args.comment
    standard=args.standard
    
    if mode in ["ecs","dcs","ecf","dcf"]:
        password=args.password
        if args.encoding:
            color_print("Encoding is not needed in mode [ecs,dcs,ecf,dcf]", "WARNING")
        
        if mode == "dcf":
            if len(inputs)>1:
                lazy_input("Only support decrypting one file at a time\n")
                exit()
            elif len(inputs)==1:
                inputs=inputs[0]
        
        if mode in ["ecs", "ecf"]:
            func(inputs, password, comment)
        else:
            func(inputs, password)
    
    elif mode in ["bes","bds"]:
        encoding=args.encoding
        if args.password:
            color_print("Password is not needed in mode [bes,bds,bef,bdf]", "WARNING")
        
        func(inputs, encoding)
    
    elif mode in ["bef","bdf","cpf","dpf"]:
        if args.password:
            color_print("Password is not needed in mode [bef,bdf,cpf,dpf]", "WARNING")
        if args.encoding:
            color_print("Encoding is not needed in mode [bef,bdf,cpf,dpf]", "WARNING")
        
        if mode in ["bdf", "dpf"]:
            if len(inputs)>1:
                lazy_input("Only support decoding one thing at a time\n")
                exit()
            elif len(inputs)==1:
                inputs=inputs[0]
        
        func(inputs)
    
    elif mode=="les":
        func(inputs, standard)
    elif mode=="lds":
        func(inputs)
    
def load_config():
    global WIDTH
    global DELAY_NORMAL
    global DELAY_STOP
    global ITERATION

    root = os.path.dirname(__file__)
    ini_path=os.path.join(root,"UserSetting.ini")
    config = configparser.ConfigParser()
    config.read(ini_path)

    try:
        WIDTH=config.getint("DEFAULT", "WIDTH", fallback=32)
    except:
        pass
    config.set("DEFAULT", "WIDTH", str(WIDTH))

    try:
        DELAY_NORMAL=config.getfloat("DEFAULT", "DELAY_NORMAL", fallback=0.07)
    except:
        pass
    config.set("DEFAULT", "DELAY_NORMAL", str(DELAY_NORMAL))

    try:
        DELAY_STOP=config.getfloat("DEFAULT", "DELAY_STOP", fallback=0.56)
    except:
        pass
    config.set("DEFAULT", "DELAY_STOP", str(DELAY_STOP))

    try:
        ITERATION=config.getint("DEFAULT", "ITERATION", fallback=48000)
    except:
        pass
    config.set("DEFAULT", "ITERATION", str(ITERATION))

    with open(ini_path, "w") as configfile:
        config.write(configfile)

# https://www.bilibili.com/video/BV1rA411g7q8
taunts_and_responses=[
    ("阿偉你又在打電動喔，休息一下吧，去看看書好不好？", "煩吶。"),
    ("我在跟你講話，有沒有聽到？", "你不要煩好不好！"),
    ("我才說你兩句你就說我煩，我只希望你能夠好好用功讀書，整天只看到你在這邊打電動！", "靠，輸了啦，都是你害的啦，拜託！")
]

# https://zh.moegirl.org.cn/野兽先辈
李田所="""
       　  　▃▆█▇▄▖
　 　 　 ▟◤▖　　　◥█▎
   　 ◢◤　 ▐　　　 　▐▉
　 ▗◤　　　▂　▗▖　　▕█▎
　◤　▗▅▖◥▄　▀◣　　█▊
▐　▕▎◥▖◣◤　　　　◢██
█◣　◥▅█▀　　　　▐██◤
▐█▙▂　　     　◢██◤
◥██◣　　　　◢▄◤
 　　▀██▅▇▀
"""

VERSION="1.0.0.7"
WIDTH=32
DELAY_NORMAL=0.07
DELAY_STOP=0.56
ITERATION=48000
OPEN_EXPLOER=True
mode_dict={
    "ecs": EncryptString,
    "dcs": DecryptString,
    "ecf": EncryptFile,
    "dcf": DecryptFile,
    "bes": Base64EncodeString,
    "bds": Base64DecodeString,
    "bef": Base64EncodeFile,
    "bdf": Base64DecodeFile,
    "cpf": CompressFile,
    "dpf": DecompressFile,
    "les": LeetEncodeString,
    "lds": LeetDecodeString,
}

load_config()

if __name__=="__main__":
    os.chdir(os.path.dirname(__file__))
    os.system("chcp 65001")

    import argparse

    parser = argparse.ArgumentParser(description="""
        Encrypt String                  ecs
        Decrypt String                  dcs
        Encrypt File                    ecf
        Decrypt File                    dcf
        Base64 Encode String            bes
        Base64 Decode String            bds
        Base64 Encode File              bef
        Base64 Decode File              bdf
        Compress File                   cpf
        Decompress File                 dpf
        Leet Encode String              les
        Leet Decode String              lds
    """, formatter_class=argparse.RawTextHelpFormatter, argument_default=argparse.SUPPRESS)

    parser.add_argument('inputs', type=str, nargs="*", default=None, help='inputs')
    parser.add_argument('-m', dest="mode", type=str, choices=mode_dict.keys(), default="Console", help='choose a mode, or it will run in console')
    parser.add_argument('-p', dest="password", nargs="*", type=str, default=None, help='password for ecs, dcs, ecf, dcf')
    parser.add_argument('-c', dest="comment", nargs="*", type=str, default=None, help='comment for ecs, ecf')
    parser.add_argument('-e', dest="encoding", type=str, default=None, help='encoding for bes, bds')
    parser.add_argument('-s', dest="standard", action="store_true", default=False, help='standard for les')
    args = parser.parse_args()
    if args.mode!="Console":
        OPEN_EXPLOER=False
        Command(args)
    else:
        OPEN_EXPLOER=True
        Console()