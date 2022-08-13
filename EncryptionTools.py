import codecs
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64, pickle
import zipfile
import os
import pyperclip
import blosc
import typing
import chardet

def Generate_Key(password):
    """
    根据password生成一个固定的salt，用salt生成一个PBKDF2，用PBKDF2和password生成key
    所以给定一个固定的password，将返回那个固定的key。
    """
    salt=password.encode()[::-1]
    password=password.encode()
    kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
    key=base64.urlsafe_b64encode(kdf.derive(password))
    return key

def Fernet_Encrypt_Save(password: str, data, file_path):
    try:
        if type(data)!=bytes:
            data=pickle.dumps(data)
        
        key=Generate_Key(password)

        fer=Fernet(key)
        encrypt_data=fer.encrypt(data)
        
        if not os.path.exists(os.path.dirname(os.path.abspath(file_path))):
            os.makedirs(os.path.dirname(file_path))
        
        with open(file_path,"wb") as f:
            f.write(blosc.compress(encrypt_data, cname="zlib"))
        
        return True
    except Exception as e:
        print(e)
        return False

def Fernet_Decrypt_Load(password: str, file_path):
    try:
        key=Generate_Key(password)
        
        with open(file_path,"rb") as f:
            data=blosc.decompress(f.read())
        
        fer=Fernet(key)
        decrypt_data=fer.decrypt(data)
        try:
            decrypt_data=pickle.loads(decrypt_data)
        except:
            pass

        return decrypt_data
    except:
        return False

def Fernet_Encrypt(password: str, data):
    try:
        if type(data)!=bytes:
            data=pickle.dumps(data)
        
        key=Generate_Key(password)

        fer=Fernet(key)
        encrypt_data=fer.encrypt(data)
        
        return encrypt_data
    except:
        return False

def Fernet_Decrypt(password: str, data: bytes):
    try:
        key=Generate_Key(password)
        
        fer=Fernet(key)
        decrypt_data=fer.decrypt(data)
        
        try:
            decrypt_data=pickle.loads(decrypt_data)
        except:
            pass

        return decrypt_data
    except:
        return False

def Base64_Encode(thing, width=40, encoding_for_str="utf-8") -> str:
    if type(thing)==bytes:
        res=base64.b64encode(thing).decode("ascii")
    elif type(thing)==str:
        res=base64.b64encode(bytes(thing, encoding_for_str)).decode("ascii")
    else:
        res=base64.b64encode(pickle.dumps(thing)).decode("ascii")

    if type(width)==int:
        return "\n".join([ res[i:i+width] for i in range(0, len(res), width)])
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

def Base64_Encode_Save(thing, file_path, width=40, encoding_for_str="utf-8"):
    with open(file_path, "w") as f:
        f.write(Base64_Encode(thing, width, encoding_for_str))

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
            elif os.path.isfile(fp):
                myzip.write(
                    fp,
                    os.path.basename(fp)
                )

def open_explorer(file_path):
    os.popen("explorer /select,\"%s\""%file_path)

def EncryptString():
    os.system("cls")

    print("Mode: Encrypt String\n")
    print("Input raw string (end with a new line with Ctrl+D):")
    print("-"*50)

    sentinel = ""
    # Raw_thing = '\n'.join(iter(lazy_input, sentinel))
    Raw_thing=""
    while True:
        c = lazy_input()
        if c!=False:
            if c == sentinel:
                Raw_thing=Raw_thing[:-1]
                break
            else:
                Raw_thing += c+"\n"
        else:
            Raw_thing=""
            break

    if Raw_thing:
        os.system("cls")
        print("Mode: Encrypt String\n")
        password = lazy_input("Input password: ")
        if password!=False:
            Processed_thing = Fernet_Encrypt(password, Raw_thing).decode("ascii")
            pyperclip.copy(Processed_thing)
            lazy_input("The encrypted string is in your clipboard!\nPress Enter to go back...")

def DecryptString():
    WRONG=False
    while True:
        if WRONG==False:
            os.system("cls")
            print("Mode: Decrypt String\n")
            print("Input encrypted string:")
            print("-"*50)
            Processed_thing = lazy_input()
            if Processed_thing:
                try:
                    Processed_thing = Processed_thing.encode(encoding="ascii")
                except Exception as e:
                    os.system("cls")
                    print("Mode: Decrypt String\n")
                    print(e)
                    lazy_input()
                    break
            else:
                break

            os.system("cls")
            print("Mode: Decrypt String\n")
            password = lazy_input("Input password: ")
        else:
            password = lazy_input("Wrong Password!!!\nTry again (or Press Ctrl+C to quit): ")

        if password!=False:
            Raw_thing = Fernet_Decrypt(password, Processed_thing)
            if Raw_thing:
                os.system("cls")
                print("Mode: Decrypt String\n")
                print("Decryption Successed!")
                print("-"*50)
                print(Raw_thing)
                print("-"*50)
                pyperclip.copy(Raw_thing)
                lazy_input("The decrypted string is in your clipboard!\nPress Enter to go back...")
                break
            else:
                WRONG=True
                continue
        else:
            break
            
def EncryptFile():
    os.system("cls")

    print("Mode: Encrypt File\n")
    print("Input file path (end with a new line with Ctrl+D):")
    print("-"*50)
    file_paths=[]
    sentinel = ""
    
    Raw_thing=""
    while True:
        c = lazy_input()
        if c!=False:
            if c == sentinel:
                break
            else:
                c=fix_path(c)
                if c:
                    if os.path.exists(c):
                        file_paths.append(c)
                        print("%s added"%c)
                    else:
                        print("%s will be ignored since it does not exist!"%c)
        else:
            file_paths=[]
            break
    
    if file_paths:

        if len(file_paths)==1 and os.path.isfile(file_paths[0]):
            single_file=True
        else:
            single_file=False
        
        if single_file:
            file_path=file_paths[0]
        else:
            print("Making zip file...")
            file_path=file_paths[0]+".zip"
            zip_files(file_path, file_paths)
        
        try:
            with open(file_path, "rb") as f:
                Raw_thing=f.read()
        except Exception as e:
            print(e)
            if not single_file:
                os.remove(file_path)
            lazy_input()
            return
        
        if not single_file:
            os.remove(file_path)
        
        os.system("cls")
        print("Mode: Encrypt File\n")
        password = lazy_input("Input password: ")
        if password!=False:
            print("Encrypting...")
            file_path = file_path+".encrypt"
            Fernet_Encrypt_Save(password, Raw_thing, file_path)
            open_explorer(file_path)
            lazy_input("The encrypted file is saved to %s!\nPress Enter to go back..."%file_path)

def DecryptFile():
    WRONG=False
    while True:
        if WRONG==False:
            os.system("cls")
            print("Mode: Decrypt File\n")
            file_path=lazy_input("Input encrypted file path: ")
            if file_path:
                file_path=fix_path(file_path)
                try:
                    with open(file_path,"rb") as f:
                        Processed_thing=blosc.decompress(f.read())
                except Exception as e:
                    print(e)
                    lazy_input()
                    break
            else:
                break

            os.system("cls")
            print("Mode: Decrypt File\n")
            password = lazy_input("Input password: ")
        else:
            password = lazy_input("Wrong Password!!!\nTry again (or Press Ctrl+C to quit): ")
        
        if password!=False:
            Raw_thing = Fernet_Decrypt(password, Processed_thing)
            if Raw_thing:
                os.system("cls")
                print("Mode: Decrypt File\n")
                print("Decryption Successed!")
                file_path = file_path.replace(".encrypt","")
                name, ext = os.path.splitext(file_path)
                name = name+"-decrypt"
                file_path = name+ext
                with open(file_path, "wb") as f:
                    f.write(Raw_thing)
                open_explorer(file_path)
                lazy_input("The decrypted file is saved to %s!\nPress Enter to go back..."%file_path)
                break
            else:
                WRONG=True
                continue
        else:
            break
            
def Base64EncodeString():
    os.system("cls")

    print("Mode: Base64 Encode String\n")
    print("Input raw string (end with a new line with Ctrl+D):")
    print("-"*50)

    sentinel = ""
    # Raw_thing = '\n'.join(iter(lazy_input, sentinel))
    Raw_thing=""
    while True:
        c = lazy_input()
        if c!=False:
            if c == sentinel:
                Raw_thing=Raw_thing[:-1]
                break
            else:
                Raw_thing += c+"\n"
        else:
            Raw_thing=""
            break
    
    if Raw_thing:
        while True:
            try:
                os.system("cls")
                print("Mode: Base64 Encode String\n")
                encoding = lazy_input("Encoding Codec (default to utf-8): ")
                if encoding!=False:
                    encoding = encoding.strip()
                    if not encoding:
                        encoding="utf-8"
                    Processed_thing = codecs.lookup(encoding).encode(Raw_thing)[0]
                    print("Encoding with %s"%encoding)
                    Processed_thing = Base64_Encode(Processed_thing)
                    pyperclip.copy(Processed_thing)
                    lazy_input("The Base64 Encoded string is in your clipboard!\nPress Enter to go back...")
                break
            except Exception as e:
                print(e)
                lazy_input("")

def Base64DecodeString():
    os.system("cls")

    print("Mode: Base64 Decode String\n")
    print("Input Base64 Encoded string (end with a new line with Ctrl+D):")
    print("-"*50)

    sentinel = ""
    # Processed_thing = '\n'.join(iter(lazy_input, sentinel))
    Processed_thing=""
    while True:
        c = lazy_input()
        if c!=False:
            if c == sentinel:
                Processed_thing=Processed_thing[:-1]
                break
            else:
                Processed_thing += c+"\n"
        else:
            Processed_thing=""
            break
    
    if Processed_thing:
        Processed_thing = Base64_Decode(Processed_thing, bytes)
        if Processed_thing==False:
            print("Decoding Error!")
            lazy_input()
            return

        det=chardet.detect_all(Processed_thing)
        while True:
            try:
                os.system("cls")
                print("Mode: Base64 Decode String\n")
                print("Codec Detection:")
                index=0
                for i in det:
                    if index==0:
                        print("\t", "%-12s"%i["encoding"], "Confidence:", "%.2f"%i["confidence"], "Language:", i["language"], "\t<-- default")
                    else:
                        print("\t", "%-12s"%i["encoding"], "Confidence:", "%.2f"%i["confidence"], "Language:", i["language"])
                    index+=1
                
                encoding = lazy_input("Decoding Codec: ")
                if encoding!=False:
                    encoding = encoding.strip()
                    if not encoding:
                        encoding=det[0]["encoding"]
                    
                    Raw_thing = codecs.lookup(encoding).decode(Processed_thing)[0]
                    if Raw_thing:
                        print("Decoding with %s"%encoding)
                        print("-"*50)
                        print(Raw_thing)
                        print("-"*50)
                        pyperclip.copy(Raw_thing)
                        lazy_input("The Base64 Decoded string is in your clipboard!\nPress Enter to go back...")
                    else:
                        print("Decoding Error!")
                        lazy_input()
                break
            except Exception as e:
                print(e)
                lazy_input("")

def Base64EncodeFile():
    os.system("cls")

    print("Mode: Base64 Encode File\n")
    print("Input file path (end with a new line with Ctrl+D):")
    print("-"*50)
    file_paths=[]
    sentinel = ""
    
    Raw_thing=""
    while True:
        c = lazy_input()
        if c!=False:
            if c == sentinel:
                break
            else:
                c=fix_path(c)
                if c:
                    if os.path.exists(c):
                        file_paths.append(c)
                        print("%s added"%c)
                    else:
                        print("%s will be ignored since it does not exist!"%c)
        else:
            file_paths=[]
            break
    
    if file_paths:

        if len(file_paths)==1 and os.path.isfile(file_paths[0]):
            single_file=True
        else:
            single_file=False
        
        if single_file:
            file_path=file_paths[0]
        else:
            print("Making zip file...")
            file_path=file_paths[0]+".zip"
            zip_files(file_path, file_paths)
        
        try:
            with open(file_path, "rb") as f:
                Raw_thing=f.read()
        except Exception as e:
            print(e)
            if not single_file:
                os.remove(file_path)
            lazy_input()
            return
        
        if not single_file:
            os.remove(file_path)
        
        os.system("cls")
        print("Mode: Base64 Encode File\n")
        
        file_path = file_path+".encode"
        Base64_Encode_Save(Raw_thing, file_path)
        open_explorer(file_path)
        lazy_input("The Base64 Encoded file is saved to %s!\nPress Enter to go back..."%file_path)

def Base64DecodeFile():
    os.system("cls")

    print("Mode: Base64 Decode File\n")
    file_path=lazy_input("Input Base64 Encoded file path: ")
    if file_path:
        file_path=fix_path(file_path)
        try:
            Raw_thing=Base64_Decode_Load(file_path, bytes)
            if not Raw_thing:
                print("Decoding Error!")
                lazy_input()
                return
        except Exception as e:
            print(e)
            lazy_input()
            return
        
        os.system("cls")
        print("Mode: Base64 Decode File\n")
        
        file_path = file_path.replace(".encode","")
        name, ext = os.path.splitext(file_path)
        name = name+"-decode"
        file_path = name+ext
        with open(file_path, "wb") as f:
            f.write(Raw_thing)
        open_explorer(file_path)
        lazy_input("The Base64 Decoded file is saved to %s!\nPress Enter to go back..."%file_path)

def CompressFile():
    os.system("cls")

    print("Mode: Compress File\n")
    print("Input file path (end with a new line with Ctrl+D):")
    print("-"*50)
    file_paths=[]
    sentinel = ""
    
    Raw_thing=""
    while True:
        c = lazy_input()
        if c!=False:
            if c == sentinel:
                break
            else:
                c=fix_path(c)
                if c:
                    if os.path.exists(c):
                        file_paths.append(c)
                        print("%s added"%c)
                    else:
                        print("%s will be ignored since it does not exist!"%c)
        else:
            file_paths=[]
            break
    
    if file_paths:

        if len(file_paths)==1 and os.path.isfile(file_paths[0]):
            single_file=True
        else:
            single_file=False
        
        if single_file:
            file_path=file_paths[0]
        else:
            print("Making zip file...")
            file_path=file_paths[0]+".zip"
            zip_files(file_path, file_paths)

        try:
            with open(file_path, "rb") as f:
                Raw_thing=f.read()
        except Exception as e:
            print(e)
            if not single_file:
                os.remove(file_path)
            lazy_input()
            return
        
        if not single_file:
            os.remove(file_path)
        
        os.system("cls")
        print("Mode: Compress File\n")
        file_path = file_path+".compressed"
        Compress_Save(Raw_thing, file_path)
        open_explorer(file_path)
        lazy_input("The compressed file is saved to %s!\nPress Enter to go back..."%file_path)

def DecompressFile():
    os.system("cls")

    print("Mode: Decompress File\n")
    file_path=lazy_input("Input compressed file path: ")
    if file_path:
        file_path=fix_path(file_path)
        try:
            Processed_thing=Decompress_Load(file_path)
        except Exception as e:
            print(e)
            lazy_input()
            return
        
        os.system("cls")
        print("Mode: Decompress File\n")
        
        file_path = file_path.replace(".compressed","")
        name, ext = os.path.splitext(file_path)
        name = name+"-decompress"
        file_path = name+ext
        with open(file_path, "wb") as f:
            f.write(Processed_thing)
        open_explorer(file_path)
        lazy_input("The decompressed file is saved to %s!\nPress Enter to go back..."%file_path)


os.system("chcp 65001")
os.system("cls")
if __name__=="__main__":

    while True:
        os.system("cls")
        mode = lazy_input("""Select Mode:

        1. Encrypt String           5. Base64 Encode String             9. Compress File
        2. Decrypt String           6. Base64 Decode String             10. Decompress File
        3. Encrypt File             7. Base64 Encode File
        4. Decrypt File             8. Base64 Decode File

                                        Exit: Ctrl+C

                                            """)
        
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
        else:
            continue