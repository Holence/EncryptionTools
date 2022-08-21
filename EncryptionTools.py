import codecs
import uuid
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

OPEN_EXPLOER=True
WIDTH=32

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

def Base64_Encode(thing, encoding_for_str="utf-8") -> str:
    if type(thing)==bytes:
        res=base64.b64encode(thing).decode("ascii")
    elif type(thing)==str:
        res=base64.b64encode(bytes(thing, encoding_for_str)).decode("ascii")
    else:
        res=base64.b64encode(pickle.dumps(thing)).decode("ascii")

    return "\n".join([ res[i:i+WIDTH] for i in range(0, len(res), WIDTH)])

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

def unzip_file(zip_file_path, dst_path):
    
    safe=True
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            for member in zip_file.infolist():
                file_path=os.path.join(dst_path, member.filename)
                if os.path.exists(file_path):
                    print("%s already exsit"%(file_path))
                    safe=False

            if safe:
                zip_file.extractall(dst_path)
            else:
                lazy_input("Zip file will be retained. Process terminated...")
        return safe
    except Exception as e:
        raise e

def open_explorer(file_path):
    if OPEN_EXPLOER:
        os.popen("explorer /select,\"%s\""%file_path)

def EncryptString(input_list: list = None, password: str = None):
    os.system("cls")

    print("Mode: Encrypt String\n")
    print("Input raw string (end with a new line with Ctrl+D):")
    print("-"*50)

    sentinel = ""
    # Raw_thing = '\n'.join(iter(lazy_input, sentinel))
    if not input_list:
        input_list=[]
        while True:
            c = lazy_input()
            if c!=False:
                if c == sentinel:
                    break
                else:
                    input_list.append(c)
            else:
                input_list=[]
                break
    print("-"*50)
    print()

    if input_list:
        if not password:
            password = lazy_input("Input password: ")
        
        if password!=False:
            s = "\n".join(input_list)
            string_encrypt = Fernet_Encrypt(password, s).decode("ascii")
            string_encrypt = "\n".join([ string_encrypt[i:i+WIDTH] for i in range(0, len(string_encrypt), WIDTH)])
            pyperclip.copy(string_encrypt)
            lazy_input("The encrypted string is in your clipboard!\nPress Enter to go back...")

def DecryptString(input_list: str = None, password: str = None):
    WRONG=False
    current_password = password
    
    os.system("cls")
    print("Mode: Decrypt String\n")
    print("Input encrypted string (end with a new line with Ctrl+D):")
    print("-"*50)
    
    sentinel = ""
    # Raw_thing = '\n'.join(iter(lazy_input, sentinel))
    if not input_list:
        input_list=[]
        while True:
            c = lazy_input()
            if c!=False:
                if c == sentinel:
                    break
                else:
                    input_list.append(c)
            else:
                input_list=[]
                break
    
    if input_list:
        s = "\n".join(input_list)
        try:
            string_bytes = s.encode(encoding="ascii")
        except Exception as e:
            os.system("cls")
            print("Mode: Decrypt String\n")
            print(e)
            lazy_input()
            return
    else:
        return
    
    while True:
        if WRONG==False:
            os.system("cls")
            print("Mode: Decrypt String\n")
            if not current_password:
                current_password = lazy_input("Input password: ")
        else:
            current_password = lazy_input("Wrong Password!!!\nTry again (or Press Ctrl+C to quit): ")

        if current_password!=False:
            string_decrypt = Fernet_Decrypt(current_password, string_bytes)
            if string_decrypt:
                os.system("cls")
                print("Mode: Decrypt String\n")
                print("Decryption Successed!")
                print("-"*50)
                print(string_decrypt)
                print("-"*50)
                pyperclip.copy(string_decrypt)
                lazy_input("The decrypted string is in your clipboard!\nPress Enter to go back...")
                break
            else:
                WRONG=True
                continue
        else:
            break
            
def EncryptFile(file_paths: list = None, password: str = None, comment: list = None):
    os.system("cls")

    print("Mode: Encrypt File\n")
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
                    if os.path.exists(c):
                        file_paths.append(c)
                        print("%s added"%c)
                    else:
                        print("%s will be ignored since it does not exist!"%c)
            else:
                file_paths=[]
                break
    else:
        input_file_path=file_paths
        file_paths=[]
        for c in input_file_path:
            c=fix_path(c)
            if os.path.exists(c):
                print("%s added"%c)
                file_paths.append(c)
            else:
                print("%s will be ignored since it does not exist!"%c)
    print("-"*50)
    print()

    if file_paths:
        
        if not password:
            password = lazy_input("Input password: ")
        
        if password!=False:
            
            print("Making zip file...")
            zip_file_path=file_paths[0]+".zip"
            zip_files(zip_file_path, file_paths)
            
            try:
                with open(zip_file_path, "rb") as f:
                    files_bytes=f.read()
            except Exception as e:
                print(e)
                os.remove(zip_file_path)
                lazy_input()
                return
            
            os.remove(zip_file_path)

            os.system("cls")
            print("Input comment (end with a new line with Ctrl+D):")
            print("-"*50)
            if not comment:
                comment=[]
                while True:
                    c = lazy_input()
                    if c!=False:
                        if c == sentinel:
                            break
                        else:
                            comment.append(c)
                    else:
                        comment=[]
                        break
            print("-"*50)
            print()

            if comment:
                os.system("cls")
                print("Encrypting...")
                
                comment = "\n".join(comment)
                encrypted_bytes = Fernet_Encrypt(password, files_bytes)
                dst_file_path = file_paths[0]+".encrypt"
                
                packed_bytes=pickle.dumps({
                    "comment": comment,
                    "bytes": encrypted_bytes
                })
                with open(dst_file_path,"wb") as f:
                    f.write(blosc.compress(packed_bytes, cname="zlib"))

                open_explorer(dst_file_path)
                lazy_input("The encrypted file is saved to %s!\nPress Enter to go back..."%dst_file_path)

def DecryptFile(file_path: str = None, password: str = None):
    WRONG=False
    current_password = password
    while True:
        if WRONG==False:
            os.system("cls")
            print("Mode: Decrypt File\n")

            if not file_path:
                file_path=lazy_input("Input encrypted file path: ")
                if file_path!=False:
                    file_path=fix_path(file_path)
                else:
                    break
            try:
                print("Opening encrypted file...")
                with open(file_path,"rb") as f:
                    packed_bytes=pickle.loads(blosc.decompress(f.read()))
            except Exception as e:
                print(e)
                lazy_input()
                break
            
            comment=packed_bytes["comment"]
            file_encrypt=packed_bytes["bytes"]

            os.system("cls")
            print("Mode: Decrypt File\n")
            print("Comment:")
            print("-"*50)
            print(comment)
            print("-"*50)
            if not current_password:
                current_password = lazy_input("Input password: ")
        else:
            current_password = lazy_input("Wrong Password!!!\nTry again (or Press Ctrl+C to quit): ")
        
        if current_password!=False:
            file_decrypt = Fernet_Decrypt(current_password, file_encrypt)
            if file_decrypt:
                os.system("cls")
                print("Mode: Decrypt File\n")
                print("Decryption Successed!")
                file_path = file_path.replace(".encrypt","")

                try:
                    zip_file_path = file_path+".zip"
                    with open(zip_file_path, "wb") as f:
                        f.write(file_decrypt)
                    if unzip_file(zip_file_path, os.path.dirname(file_path)):
                        os.remove(zip_file_path)
                        open_explorer(file_path)
                        lazy_input("The decrypted file is saved to %s!\nPress Enter to go back..."%file_path)
                    break
                except Exception as e:
                    print(e)
                
                os.remove(zip_file_path)
                print("File cannot decode as zip, it will be saved to a pickle file")
                if os.path.exists(file_path+".pickle"):
                    print("%s already exsits!"%file_path)
                    n,e = os.path.splitext(file_path)
                    n = n+str(uuid.uuid4())
                    file_path = n+e
                file_path = file_path+".pickle"
                with open(file_path, "wb") as f:
                    pickle.dump(file_decrypt, f)
                open_explorer(file_path)
                lazy_input("File saved to %s\n"%file_path)
                break
            else:
                WRONG=True
                continue
        else:
            break

def Base64EncodeString(input_list: list = None, encoding: str = None):
    os.system("cls")

    print("Mode: Base64 Encode String\n")
    print("Input raw string (end with a new line with Ctrl+D):")
    print("-"*50)

    sentinel = ""
    # Raw_thing = '\n'.join(iter(lazy_input, sentinel))
    if not input_list:
        input_list=[]
        while True:
            c = lazy_input()
            if c!=False:
                if c == sentinel:
                    break
                else:
                    input_list.append(c)
            else:
                input_list=[]
                break
    print("-"*50)
    print()

    if input_list:
        s = "\n".join(input_list)
        while True:

            if not encoding:
                encoding = lazy_input("Encoding Codec (default to utf-8): ")
            
            if encoding!=False:
                encoding = encoding.strip()
                if not encoding:
                    encoding="utf-8"
                
                try:
                    string_encode = codecs.lookup(encoding).encode(s)[0]
                    print("Encoding with %s"%encoding)
                    string_encode = Base64_Encode(string_encode)
                    pyperclip.copy(string_encode)
                    lazy_input("The Base64 Encoded string is in your clipboard!\nPress Enter to go back...")
                    break
                except Exception as e:
                    encoding=False
                    print(e)
                    lazy_input("")
            else:
                break

def Base64DecodeString(input_list: list = None, encoding: str = None):
    os.system("cls")

    print("Mode: Base64 Decode String\n")
    print("Input Base64 Encoded string (end with a new line with Ctrl+D):")
    print("-"*50)

    sentinel = ""
    # Raw_thing = '\n'.join(iter(lazy_input, sentinel))
    if not input_list:
        input_list=[]
        while True:
            c = lazy_input()
            if c!=False:
                if c == sentinel:
                    break
                else:
                    input_list.append(c)
            else:
                input_list=[]
                break
    
    if input_list:
        s = "\n".join(input_list)
        string_B_decode = Base64_Decode(s, bytes)
        if string_B_decode==False:
            print("Decoding Error!")
            lazy_input()
            return

        det=chardet.detect_all(string_B_decode)
        while True:
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
                    lazy_input("The Base64 Decoded string is in your clipboard!\nPress Enter to go back...")
                    break
                except Exception as e:
                    print(e)
                    encoding=False
                    lazy_input("")
            else:
                break

def Base64EncodeFile(file_paths: list = None):
    os.system("cls")

    print("Mode: Base64 Encode File\n")
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
                    if os.path.exists(c):
                        file_paths.append(c)
                        print("%s added"%c)
                    else:
                        print("%s will be ignored since it does not exist!"%c)
            else:
                file_paths=[]
                break
    else:
        input_file_path=file_paths
        file_paths=[]
        for c in input_file_path:
            c=fix_path(c)
            if os.path.exists(c):
                print("%s added"%c)
                file_paths.append(c)
            else:
                print("%s will be ignored since it does not exist!"%c)
    print("-"*50)
    print()

    if file_paths:

        print("Making zip file...")
        zip_file_path=file_paths[0]+".zip"
        zip_files(zip_file_path, file_paths)
        
        try:
            with open(zip_file_path, "rb") as f:
                files_bytes=f.read()
        except Exception as e:
            print(e)
            os.remove(zip_file_path)
            lazy_input()
            return
        
        os.remove(zip_file_path)
        
        dst_file_path = file_paths[0]+".encode"
        Base64_Encode_Save(files_bytes, dst_file_path)
        open_explorer(dst_file_path)
        lazy_input("The Base64 Encoded file is saved to %s!\nPress Enter to go back..."%dst_file_path)

def Base64DecodeFile(file_path: str = None):
    os.system("cls")

    print("Mode: Base64 Decode File\n")
    if not file_path:
        file_path=lazy_input("Input Base64 Encoded file path: ")
        if file_path:
            file_path=fix_path(file_path)
        else:
            return
    try:
        file_bytes=Base64_Decode_Load(file_path, bytes)
        if not file_bytes:
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
    
    try:
        zip_file_path = file_path+".zip"
        with open(zip_file_path, "wb") as f:
            f.write(file_bytes)
        if unzip_file(zip_file_path, os.path.dirname(file_path)):
            os.remove(zip_file_path)
            open_explorer(file_path)
            lazy_input("The Base64 Decoded file is saved to %s!\nPress Enter to go back..."%file_path)
        return
    except Exception as e:
        print(e)
    
    os.remove(zip_file_path)
    print("File cannot decode as zip, it will be saved to a pickle file")
    if os.path.exists(file_path+".pickle"):
        print("%s already exsits!"%file_path)
        n,e = os.path.splitext(file_path)
        n = n+str(uuid.uuid4())
        file_path = n+e
    file_path = file_path+".pickle"
    with open(file_path, "wb") as f:
        pickle.dump(file_bytes, f)
    open_explorer(file_path)
    lazy_input("File saved to %s\n"%file_path)

def CompressFile(file_paths: list = None):
    os.system("cls")

    print("Mode: Compress File\n")
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
                    if os.path.exists(c):
                        file_paths.append(c)
                        print("%s added"%c)
                    else:
                        print("%s will be ignored since it does not exist!"%c)
            else:
                file_paths=[]
                break
    else:
        input_file_path=file_paths
        file_paths=[]
        for c in input_file_path:
            c=fix_path(c)
            if os.path.exists(c):
                print("%s added"%c)
                file_paths.append(c)
            else:
                print("%s will be ignored since it does not exist!"%c)
    print("-"*50)
    print()

    if file_paths:
        
        print("Making zip file...")
        zip_file_path=file_paths[0]+".zip"
        zip_files(zip_file_path, file_paths)

        try:
            with open(zip_file_path, "rb") as f:
                files_bytes=f.read()
        except Exception as e:
            print(e)
            os.remove(zip_file_path)
            lazy_input()
            return
        
        os.remove(zip_file_path)
        
        dst_file_path = file_paths[0]+".compress"
        Compress_Save(files_bytes, dst_file_path)
        open_explorer(dst_file_path)
        lazy_input("The compressed file is saved to %s!\nPress Enter to go back..."%dst_file_path)

def DecompressFile(file_path: str = None):
    os.system("cls")

    print("Mode: Decompress File\n")
    if not file_path:
        file_path=lazy_input("Input compressed file path: ")
        if file_path:
            file_path=fix_path(file_path)
        else:
            return
    
    try:
        file_bytes=Decompress_Load(file_path)
    except Exception as e:
        print(e)
        lazy_input()
        return
    
    os.system("cls")
    print("Mode: Decompress File\n")
    file_path = file_path.replace(".compress","")
    
    try:
        zip_file_path = file_path+".zip"
        with open(zip_file_path, "wb") as f:
            f.write(file_bytes)
        
        if unzip_file(zip_file_path, os.path.dirname(file_path)):
            os.remove(zip_file_path)
            open_explorer(file_path)
            lazy_input("The decompressed file is saved to %s!\nPress Enter to go back..."%file_path)
        return
    except Exception as e:
        print(e)

    os.remove(zip_file_path)
    print("File cannot decode as zip, it will be saved to a pickle file")
    if os.path.exists(file_path+".pickle"):
        print("%s already exsits!"%file_path)
        n,e = os.path.splitext(file_path)
        n = n+str(uuid.uuid4())
        file_path = n+e
    file_path = file_path+".pickle"
    with open(file_path, "wb") as f:
        pickle.dump(file_bytes, f)
    open_explorer(file_path)
    lazy_input("File saved to %s\n"%file_path)

def Console():
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

def Command(args):
    
    mode=args.mode
    func=mode_dict[mode]
    inputs=args.inputs
    comment=args.comment
    
    if mode in ["ecs","dcs","ecf","dcf"]:
        password=args.password
        if args.encoding:
            print("Encoding is not needed in mode [ecs,dcs,ecf,dcf]")
        
        if mode == "dcf":
            if len(inputs)>1:
                lazy_input("Only support decrypting one file at a time\n")
                exit()
            elif len(inputs)==1:
                inputs=inputs[0]
        
        if mode == "ecf":
            func(inputs, password, comment)
        else:
            func(inputs, password)
    
    elif mode in ["bes","bds"]:
        encoding=args.encoding
        if args.password:
            print("Password is not needed in mode [bes,bds,bef,bdf]")
        
        func(inputs, encoding)
    
    elif mode in ["bef","bdf","cpf","dpf"]:
        if args.password:
            print("Password is not needed in mode [bef,bdf,cpf,dpf]")
        if args.encoding:
            print("Encoding is not needed in mode [bef,bdf,cpf,dpf]")
        
        if mode in ["bdf", "dpf"]:
            if len(inputs)>1:
                lazy_input("Only support decoding one thing at a time\n")
                exit()
            elif len(inputs)==1:
                inputs=inputs[0]
        
        func(inputs)


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
    }

if __name__=="__main__":
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
    """, formatter_class=argparse.RawTextHelpFormatter, argument_default=argparse.SUPPRESS)

    parser.add_argument('inputs', type=str, nargs="*", default=None, help='inputs')
    parser.add_argument('-m', dest="mode", type=str, choices=mode_dict.keys(), default="Console", help='choose a mode, or it will run in console')
    parser.add_argument('-p', dest="password", type=str, default=None, help='password for ecs, dcs, ecf, dcf')
    parser.add_argument('-e', dest="encoding", type=str, default=None, help='encoding for bes, bds')
    parser.add_argument('-c', dest="comment", nargs="*", type=str, default=None, help='comment for ecf')
    
    args = parser.parse_args()
    if args.mode!="Console":
        OPEN_EXPLOER=False
        Command(args)
    else:
        OPEN_EXPLOER=True
        Console()