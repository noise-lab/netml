# -*- mode: python ; coding: utf-8 -*-
#
# see: https://github.com/pyinstaller/pyinstaller/issues/305
# see: https://github.com/pyinstaller/pyinstaller/wiki/Recipe-Setuptools-Entry-Point
#
import pkg_resources


def get_toplevel(dist):
    # get toplevel packages of distribution from metadata
    distribution = pkg_resources.get_distribution(dist)
    if distribution.has_metadata('top_level.txt'):
        return list(distribution.get_metadata('top_level.txt').split())
    else:
        return []


def Entrypoint(dist, group, name, **kwargs):
    kwargs.setdefault('pathex', [])
    kwargs.setdefault('hiddenimports', [])

    packages = [get_toplevel(distribution) for distribution in kwargs['hiddenimports']]

    # get the entry point
    ep = pkg_resources.get_entry_info(dist, group, name)

    # insert path of the egg at the verify front of the search path
    kwargs['pathex'] = [ep.dist.location] + kwargs['pathex']

    # script name must not be a valid module name to avoid name clashes on import
    script_path = os.path.join(workpath, name + '-script.py')

    print("creating script for entry point", dist, group, name)
    with open(script_path, 'w') as fh:
        print("import", ep.module_name, file=fh)
        print("%s.%s()" % (ep.module_name, '.'.join(ep.attrs)), file=fh)
        for package in packages:
            print("import", package, file=fh)

    return Analysis(
        [script_path] + kwargs.get('scripts', []),
        **kwargs
    )


block_cipher = None

a = Entrypoint('netml', 'console_scripts', 'netml')

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='netml',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='netml')
