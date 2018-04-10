from __future__ import print_function
from Cryptodome.Hash import CMAC
from Cryptodome.Cipher import AES
import os,sys,random,hashlib
from binascii import hexlify

keyx=0x6FBB01F872CAF9C01834EEC04065EE53
keyy=0x0 #get this from movable.sed - console unique
F128=0xffffffffffffffffffffffffffffffff
C   =0x1FF9E9AAC5FE0408024591DC5D52768A
cmac_keyx=0xB529221CDDB5DB5A1BF26EFF2041E875

DIR="decrypted_sections/"
BM=0x20         #block metadata size https://www.3dbrew.org/wiki/DSiWare_Exports (a bunch of info in this script is sourced here)
BANNER=0x0
BANNER_SIZE=0x4000
HEADER=BANNER+BANNER_SIZE+BM
HEADER_SIZE=0xF0
FOOTER=HEADER+HEADER_SIZE+BM
FOOTER_SIZE=0x4E0
TMD=FOOTER+FOOTER_SIZE+BM
content_sizelist=[0]*11
content_namelist=["tmd","srl.nds","2.bin","3.bin","4.bin","5.bin","6.bin","7.bin","8.bin","public.sav","banner.sav"]

if (len(sys.argv) != 3):
	print("Usage: python TADpole.py <dsiware export> <dump or rebuild (d or r)>\n")

with open(sys.argv[1],"rb+") as f:
	tad=f.read()
	if(len(tad)<0x20000):
		print("Error: input dsiware %s is way too small, is this really a dsiware.bin?" % sys.argv[1])
		sys.exit(1)

tad_sections=[b""]*14

if sys.version_info[0] >= 3:
	# Python 3
	def bytechr(c):
		return bytes([c])
else:
	# Python 2
	bytechr = chr

def get_keyy():
	global keyy
	realseed=0
	with open("resources/movable.sed","rb") as f:
		msedlen=len(f.read())
		if(msedlen != 0x140 and msedlen != 0x120):
			print("Error: movable.sed is the wrong size - are you sure this is a movable.sed?")
			sys.exit(1)
		f.seek(0)
		if(f.read(4)==b"SEED"):
			realseed=1
			f.seek(0)
		f.seek(0x110)
		temp=f.read(0x10)
		keyy=int(hexlify(temp), 16)
	if(realseed):
		print("Real movable.sed detected, cleaning non-keyy contents for safety")
		print("DO NOT import this to a real 3DS!")
		with open("resources/movable.sed","wb") as f:
			f.write((b"\x00"*0x110)+temp+(b"\x00"*0x20))

def int16bytes(n):
	if sys.version_info[0] >= 3:
		return n.to_bytes(16, 'big')  # Python 3
	else:
		s=b"" 						  # Python 2
		for i in range(16):
			s=chr(n & 0xFF)+s
			n=n>>8
		return s
	
def int2bytes(n):
	s=bytearray(4)
	for i in range(4):
		s[i]=n & 0xFF
		n=n>>8
	return s

def bytes2int(s):
	n=0
	for i in range(4):
		n+=ord(s[i:i+1])<<(i*8)
	return n
	
def endian(n, size):
	new=0
	for i in range(size):
		new <<= 8
		new |= (n & 0xFF)
		n >>= 8
	return new
		
def add_128(a, b):
	return (a+b) & F128

def rol_128(n, shift):
	for i in range(shift):
		left_bit=(n & 1<<127)>>127
		shift_result=n<<1 & F128
		n=shift_result | left_bit
	return n

def normalkey(x,y):     	#3ds aes engine - curtesy of rei's pastebin google doc, curtesy of plutoo from 32c3
	n=rol_128(x,2) ^ y  	#F(KeyX, KeyY) = (((KeyX <<< 2) ^ KeyY) + 1FF9E9AAC5FE0408024591DC5D52768A) <<< 87
	n=add_128(n,C)      	#https://pastebin.com/ucqXGq6E
	n=rol_128(n,87)     	#https://smealum.github.io/3ds/32c3/#/113
	return n
	
def decrypt(message, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv )
	return cipher.decrypt(message)

def encrypt(message, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv )
	return cipher.encrypt(message)
	
def dump_section(data_offset, size, filename):
	iv=tad[data_offset+size+0x10:data_offset+size+0x20]
	key=normalkey(keyx,keyy)
	result=decrypt(tad[data_offset:data_offset+size],int16bytes(key),iv)
	with open(filename,"wb") as f:
		f.write(result)
	print("%08X  %08X  %s" % (data_offset, size, filename))

def check_keyy(keyy_offset):
	global keyy
	tempy=endian(keyy,16)
	tempy=tempy+(keyy_offset<<64)
	tempy=endian(tempy,16)
	iv=tad[HEADER+HEADER_SIZE+0x10:HEADER+HEADER_SIZE+0x20]
	key=normalkey(keyx, tempy)
	result=decrypt(tad[HEADER:HEADER+HEADER_SIZE],int16bytes(key),iv)
	if(b"\x33\x46\x44\x54" not in result[:4]):
		print("wrong -- keyy offset: %d" % (keyy_offset))
		return 1
	keyy=tempy
	print("correct! -- keyy offset: %d" % (keyy_offset))
	return 0
	#print("%08X  %08X  %s" % (data_offset, size, filename))
	
def fix_movable():
	temp=b""
	print("correcting movable.sed ...")
	with open("resources/movable.sed","rb+") as f:
		bak=f.read()
		f.seek(0)
		f.write(b"\x00"*0x110+int16bytes(keyy)+b"\x00"*0x20)
	with open("resources/movable_bak.sed","wb") as f:
		f.write(bak)
	print("your original movable.sed has been overwritten and a new movable_bak.sed created with the old data")

def get_content_sizes():
	with open(DIR+"header.bin","rb") as f:
		f.seek(0x48)
		temp=f.read(0x2C)
	for i in range(11):
		offset=i*4
		content_sizelist[i]=bytes2int(temp[offset:offset+4])
		if(i==0):
			pad=16-(content_sizelist[i] % 16)
			content_sizelist[i]+=pad
			#this is padding the tmd section for aes-cbc blocks (16B block align)

def get_content_block(buff):
	global cmac_keyx
	hash=hashlib.sha256(buff).digest()
	key = int16bytes(normalkey(cmac_keyx, keyy))
	cipher = CMAC.new(key, ciphermod=AES)
	result = cipher.update(hash)
	return result.digest() + b''.join(bytechr(random.randint(0,255)) for _ in range(16))

def sign_footer():
	ret=0
	print("-----------Handing off to ctr-dsiwaretool...\n")
	if(sys.platform=="win32"):
		print("Windows selected")
		ret=os.system("resources\ctr-dsiwaretool.exe "+DIR+"footer.bin resources/ctcert.bin --write")
	else:
		print("Linux selected")
		ret=os.system("resources/ctr-dsiwaretool "+DIR+"footer.bin resources/ctcert.bin --write")
	print("\n-----------Returning to TADpole...")
	if  (ret==1):
		print("Error: file handling issue with %sfooter.bin" % DIR)
		sys.exit(1)
	elif(ret==2):
		print("Error: file handling issue with resources/ctcert.bin")
		sys.exit(1)
	elif(ret==3):
		print("Error: resources/ctcert.bin is invalid")
		sys.exit(1)
	elif(ret!=0):
		print("Error: unknown code "+str(ret))
		sys.exit(1)

def fix_hashes_and_sizes():
	sizes=[0]*11
	hashes=[""]*13
	footer_namelist=["banner.bin","header.bin"]+content_namelist
	for i in range(11):
		if(os.path.exists(DIR+content_namelist[i])):
			sizes[i] = os.path.getsize(DIR+content_namelist[i])
		else:
			sizes[i] = 0
	if(sizes[0]%16==0):
		sizes[0]-=0xC
	for i in range(13):
		if(os.path.exists(DIR+footer_namelist[i])):
			with open(DIR+footer_namelist[i],"rb") as f:
				hashes[i] = hashlib.sha256(f.read()).digest()
		else:
			hashes[i] = b"\x00"*0x20
			
	with open(DIR+"header.bin","rb+") as f:
		offset=0x48
		for i in range(11):
			f.seek(offset)
			f.write(int2bytes(sizes[i]))
			offset+=4
		print("header.bin fixed")
	
	with open(DIR+"footer.bin","rb+") as f:
		offset=0
		for i in range(13):
			f.seek(offset)
			f.write(hashes[i])
			offset+=0x20
		print("footer.bin fixed")
		
def rebuild_tad():
	global keyy
	full_namelist=["banner.bin","header.bin","footer.bin"]+content_namelist
	section=""
	content_block=""
	key=normalkey(keyx,keyy)
	for i in range(len(full_namelist)):
		if(os.path.exists(DIR+full_namelist[i])):
			print("encrypting "+DIR+full_namelist[i])
			with open(DIR+full_namelist[i],"rb") as f:
				section=f.read()
			content_block=get_content_block(section)
			tad_sections[i]=encrypt(section, int16bytes(key), content_block[0x10:])+content_block
	with open(sys.argv[1]+".patched","wb") as f:
		f.write(b''.join(tad_sections))
	print("Rebuilt to "+sys.argv[1]+".patched")
	print("Done.")

def inject_binary(path):
	if(os.path.exists(path+".inject")):
		print(path+".inject found, injecting to "+path+"...")
		with open(path,"rb+") as f, open(path+".inject","rb") as g:
			if(len(g.read()) > len(f.read())):
				print("WARNING: injection binary size greater than target, import may fail")
			f.seek(0)
			g.seek(0)
			f.write(g.read())

print("|TADpole by zoogie|")
print("|_______v1.5______|")
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

wkdir=sys.argv[1].upper().replace(".BIN","/",1)
if(wkdir.count('.')==0 and wkdir.count('/')==1):
	DIR=wkdir
print("Using workdir: "+DIR)

if(sys.argv[2]=="dump" or sys.argv[2]=="d"):
	if not os.path.exists(DIR):
		os.makedirs(DIR)
	get_keyy()
	print("checking keyy...")
	if(check_keyy(0)):
		print("Initial keyy failed to decrypt dsiware, trying adjacent keyys...")
		decrypted=0
		dec_error_msg=\
		"\nWARNING!!!: Your input movable.sed keyy was wrong, but a nearby keyy worked!"\
		"\nWARNING!!!: This means either you brute forced the wrong id0 or decrypted a dsiware.bin from the wrong id0"\
		"\nWARNING!!!: The former will probably work while the latter will likely fail to import to the 3ds."
		for i in range(1,21):
			if(check_keyy(i)==0):
				print(dec_error_msg)
				decrypted=1
				break
			elif(check_keyy(-i)==0):
				print(dec_error_msg)
				decrypted=1
				break
		if(decrypted==0):	
			print("Error: decryption failed - movable.sed keyy is wrong!")
			sys.exit(1)
		else:
			fix_movable()

	print("\nDumping sections...")
	print("Offset    Size      Filename")
	dump_section(BANNER, BANNER_SIZE, DIR+"banner.bin")
	dump_section(HEADER, HEADER_SIZE, DIR+"header.bin")
	dump_section(FOOTER, FOOTER_SIZE, DIR+"footer.bin")
	get_content_sizes()
	tad_offset=TMD
	for i in range(11):
		if(content_sizelist[i]):
			dump_section(tad_offset, content_sizelist[i], DIR+content_namelist[i])
			tad_offset+=(content_sizelist[i]+BM)
elif(sys.argv[2]=="rebuild" or sys.argv[2]=="r"):
	print("Rebuilding export...")
	get_keyy()
	inject_binary(DIR+"srl.nds")
	inject_binary(DIR+"public.sav")
	fix_hashes_and_sizes()
	sign_footer()
	rebuild_tad()
else:
	print("ERROR: please recheck Usage above")