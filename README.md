# EncryptionTools

A tool that integrates Fernet encryption, Base64 encoding, and Blosc compression.

Features:

- An Interactive Interface in Terminal
- CLI Commands and Parameters
- Windows Context Menu Options

Options:

| Options              | -m (mode) |
| -------------------- | --------- |
| Encrypt String       | ecs       |
| Decrypt String       | dcs       |
| Encrypt File         | ecf       |
| Decrypt File         | dcf       |
| Base64 Encode String | bes       |
| Base64 Decode String | bds       |
| Base64 Encode File   | bef       |
| Base64 Decode File   | bdf       |
| Compress File        | cpf       |
| Decompress File      | dpf       |
| Leet Encode String   | les       |
| Leet Decode String   | lds       |

# Installation

Download from [Github Release](https://github.com/Holence/EncryptionTools/releases) to get the latest build for Windows and run setup.bat as administrator.

or build with pyinstaller on your own:

`git clone https://github.com/Holence/EncryptionTools.git`

`python -m venv env_build`

`.\env_build\Scripts\activate`

`pip install -r .\requirements.txt`

`pip install pyinstaller`

build into One-Folder :

`pyinstaller .\EncryptionTools.spec`

Finally, move these 2 things into `./dist/EncryptionTools`

- yjsnpi.dll (taunting)
- leet.dll (leetspeak)
- context_menu.reg (Registry template)
- setup.bat (Add registry for context menu)
- [singleinstance.exe](https://github.com/zenden2k/context-menu-launcher/releases) (Support passing multiple files to shell context menu command)

Place `EncryptionTools` folder at anywhere you like.

Run setup.bat as administrator.

Done!

# Reference

<https://blog.sverrirs.com/2014/05/creating-cascading-menu-items-in.html>

<https://github.com/zenden2k/context-menu-launcher>
