# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(['EncryptionTools.py'],
             pathex=['./'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='EncryptionTools',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          console=True, icon="icon.ico", version='version.txt')
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=False,
               upx_exclude=[],
               name='EncryptionTools')