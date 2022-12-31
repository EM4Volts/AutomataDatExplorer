# AutomataDatExplorer
py script compilable as .exe to extract and repack exes from the file explorer


Usage:
downlaod prebuilt .exe release zip or build yourself,

extract the folder somewhere where you wont change the path to 

right click a dtt, dat or eff. > open with > select the dFs.exe 

now when double clicking the dat/dtt or eff it will open it as a folder, allowing you to change stuff, clicking the "PACK.em4v" file will repack it to its original location.

Building:

You need a valid working installation of python 3.10+ aswell as pyinstaller (https://pyinstaller.org/en/stable/)

make sure pyinstalelr is properly installed to your path

open a terminal in the same folder as the dFs.py enter "pyinstaller -i "namc.ico" .\dFs.py"

after a while you will have a built dir in the newly created dist folder.
