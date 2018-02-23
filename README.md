# Requirements
* Windows - adapting to Linux is possible
* Python 2.x.x - [official download](https://www.python.org/downloads)
* Pycryptodomex - install with `pip install pycryptodomex`
* A DSiWare export from your target console - must be DSihax injectable (see [list of injectable games](https://3ds.hacks.guide/installing-boot9strap-(dsiware-game-injection-list)))
* A `movable.sed` from your target console - see README in [latest seedminer release](https://github.com/zoogie/seedminer/releases/latest)
* A valid `ctcert.bin` with private key attached from a CFW console - see [instructions below](#obtaining-ctcertbin-plus-private-key) for guidance
* Sudokuhax injection files for TADpole - download appropriate set from [this link](https://github.com/YYoshi241/Sudokuhax-4-TADpole/releases/latest)

# Usage
NOTE: You can use [DSIHaxInjector](https://jenkins.nelthorya.net/job/DSIHaxInjector/build?delay=0sec) instead of this program. This is a cloud based version of TADpole and it's easier to use because of its user-friendly web interface. 
1. Download and extract latest release of [TADpole](https://github.com/zoogie/TADpole/releases/latest)
2. Copy the injectable DSiWare game from System Memory to your SD card via 3DS System Settings
3. Copy the exported DSiWare game from your SD card (in `your-sd-card/Nintendo 3DS/ID0/ID1/Nintendo DSiWare/`) to the extracted TADpole folder on your PC. It might look like `4b4c4455.bin`, for example. The hex number will be different of course.
4. Place `movable.sed` in `.../TADpole/resources/`
5. Place `ctcert.bin` in `.../TADpole/resources/`
6. Dump the exported DSiWare .bin by drag n dropping it on dump.bat.  
Or, in the Command Prompt after navigating to the TADpole directory:
```
python TADpole.py (8-digit hex).bin d
```
7. Place both sudokuhax injection files (`public.sav.inject` and `srl.nds.inject`) inside the generated game folder
8. Rebuild the modified game folder by drag n dropping the DSiWare .bin on rebuild.bat.  
Or, in the Command Prompt after navigating to the TADpole directory:
```
python TADpole.py (8-digit hex).bin r
```
9. Copy the built `.patched` file to the `.../Nintendo DSiWare/` folder in your SD card and replace the original DSiWare export with it by removing `.patched` from the filename
10. Proceed with steps in [Section V of 3ds.guide](https://3ds.hacks.guide/installing-boot9strap-(dsiware-game-injection))

**Note: more detailed instructions with screenshots can be found [here](http://gbatemp.net/threads/seedminer-single-system-dsiware-injection.495685/page-41#post-7830489)**

# Obtaining `ctcert.bin` plus private key
**Warning: the following steps require access to a 3DS with Custom Firmware (an already hacked 3DS)**
1. Install the `seedstarter.cia` found in the [seedminer release](https://github.com/zoogie/seedminer/releases/latest) section
2. Place [`ctcertifier.firm`](https://github.com/zoogie/seedminer_toolbox/tree/master/ctcertifier) in `/luma/payloads/` of your SD card if you have [Luma3DS](https://github.com/AuroraWright/Luma3DS/wiki/Optional-features#firm-payload-chainloader) installed or else somewhere where you can execute it via a chainloader
3. Turn on your 3DS and run `seedstarter.cia`
4. Press `Y` to dump `ctcert.bin` (missing private key) to `sdmc:/seedstarter/ctcert.bin`
5. Turn off your 3DS
6. Run `ctcertifier.firm` by holding `Start` and turning the 3DS on when you have Luma3DS installed
7. Copy `ctcert.bin` from `sdmc:/seedstarter/ctcert.bin` to your TADpole location, and put it in the `resources/` folder
8. Done

# Additional Notes
* If you perform a System Transfer from console A to console B, the `movable.sed` from console A (pre-transfer) will be identical to the `movable.sed` for console B (post-transfer).
* Examples of how to run the python commands are provided in `.bat` scripts.
* The release archives include an `.exe` if you want to avoid installing python2 or python in general.

# Thanks
* **yellows8** for [ctr-dsiwaretool](https://github.com/yellows8/ctr-dsiwaretool) and 3dbrew [documentation](https://www.3dbrew.org/wiki/DSiWare_Exports)
* **d0k3** for inspiring the creation of this tool with this [commit](https://github.com/d0k3/GodMode9/commit/ec861a7bf7c162c605aea353c0b9cebe7fa80e71)

