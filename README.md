# Requirements
* Python 2.x [link](https://www.python.org/downloads)
* Pycryptodomex -
Install with:
```
pip install pycryptodomex
```
* Note: the release archive includes an exe if you don't want to install python2 or python in general
* Windows (Adapting this to Linux shouldn't be difficult at all though)
* The movable.sed from the same console the dsiware was exported from.
Many tools allow you to dump this, but you need elevated permissions.
(Godmode9, FBI, Decrypt9, 3DS-Recovery-Tool, etc.)
* A valid CTcert+privkey. It can be obtained from any cfw 3ds. You can dump this with two steps:
1) Option Y in [seedstarter.3dsx](https://github.com/zoogie/seedminer/releases) will dump the ctcert.bin to sd root (minus privkey)
2) [ctcertifier.firm](https://github.com/zoogie/seedminer_toolbox/tree/master/ctcertifier) will append the privkey to the same ctcert.bin on sd root

Note: if you systransfer from console A to console B, the movable.sed from
console A (pre-transfer) will be identical to the movable.sed for console B 
(post-transfer).
# Usage
1. Place your dsiware export from Nintendo 3DS/ID0/ID1/Nintendo DSiWare/
inside the TADpole directory.
2. Place the movable.sed and ctcert.bin into TADpole/resources/
3. From the command prompt, inside TADpole execute:
```
python TADpole.py <dsiware export> <dump or rebuild>
```
Examples are in the provided .bat scripts

The dumped dsiware export (TAD) sections will be in <TitleID_low> dir by default.
You may edit them, but editing anything but srl.nds or public.sav is not recommended.
Also, avoid changing the size of these two files. 
You may also add srl.nds.inject or public.sav.inject and TADpole will overwrite
the target upon rebuild. Using a tool like OSFmount is recommended for public.sav
file injection, however.
# Thanks
* **yellows8** for [ctr-dsiwaretool](https://github.com/yellows8/ctr-dsiwaretool) and 3dbrew [documentation](https://www.3dbrew.org/wiki/DSiWare_Exports)
* **d0k3** for inspiring the creation of this tool with this [commit](https://github.com/d0k3/GodMode9/commit/ec861a7bf7c162c605aea353c0b9cebe7fa80e71)

