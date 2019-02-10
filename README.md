# What is this?
A program that allows you to create fake dsiware based on a valid dsiware and a movable. Attempting to install these fake dsiware will force uninstall any apps with the same titleid
# Requirements
* Windows - compiling to Linux & Mac should be easy given there are no dependancies here though
* A DSiWare export from your target console. The filename must be in the format: <8 digit hex>.bin Ex. 484E4441.bin)
* A `movable.sed` from your target console.

# Usage  
Basic Command Line usage is:
```
TADpole (8-digit hex).bin 
```

# Additional Notes
* If you perform a System Transfer from console A to console B, the `movable.sed` from console A (pre-transfer) will be identical to the `movable.sed` for console B (post-transfer).

# Thanks
* **zoogie** for TadPole as well as the idea and specifics to this exploit
* **booto** for [sav-adjust](https://github.com/booto/dsi/tree/master/save_adjust) (ecc code) and 3dbrew [documentation](https://www.3dbrew.org/wiki/DSiWare_Exports) (general dsiware export info)
* **jason0597** for about 75% of the [TAD crypto code](https://github.com/jason0597/TADPole-3DS/)
* **d0k3** for inspiring the creation of this tool with this [commit](https://github.com/d0k3/GodMode9/commit/ec861a7bf7c162c605aea353c0b9cebe7fa80e71)

# Libraries used
 * [Texas Instruments AES-128 CBC and AES CMAC functions](https://github.com/flexibity-team/AES-CMAC-RFC)
 * [ECDSA sect233r1 code (along with BigNum code)](http://git.infradead.org/?p=users/segher/wii.git)
 * [Nintendo 3DS key scrambler function](https://github.com/luigoalma/3ds_keyscrambler/blob/master/src/UnScrambler.c#L50)
