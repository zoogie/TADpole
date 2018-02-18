from __future__ import print_function
from Cryptodome.Hash import CMAC
from Cryptodome.Cipher import AES
import hashlib
import os,sys,random
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
TMD_SIZE=0xB40  #actual tmd size is 0xB34, but padded to 0xB40 to align with aes-cbc(16B block). 0xB40 is what's hashed in footer.
SRL=TMD+TMD_SIZE+BM
SRL_SIZE=0x0    #from here on, we need to get info from the header
SAV=0x0
SAV_SIZE=0x0
content_sizelist=[0]*11
content_namelist=["tmd","srl.nds","2.bin","3.bin","4.bin","5.bin","6.bin","7.bin","8.bin","public.sav","banner.sav"]

with open(sys.argv[1],"rb+") as f:
	tad=f.read()
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
	with open("resources/movable.sed","rb") as f:
		f.seek(0x110)
		temp=f.read(0x10)
		keyy=int(hexlify(temp), 16)

def int16bytes(n):
	if sys.version_info[0] >= 3:
		# Python 3
		return n.to_bytes(16, 'big')
	else:
		# Python 2
		s=b""
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

def add_128(a, b):
	return (a+b) & F128

def rol_128(n, shift):
	for i in range(shift):
		left_bit=(n & 1<<127)>>127
		shift_result=n<<1 & F128
		n=shift_result | left_bit
	return n

#3ds aes engine - curtesy of rei's pastebin google doc, curtesy of plutoo from 32c3
#F(KeyX, KeyY) = (((KeyX <<< 2) ^ KeyY) + 1FF9E9AAC5FE0408024591DC5D52768A) <<< 87
#https://pastebin.com/ucqXGq6E
#https://smealum.github.io/3ds/32c3/#/113
def normalkey(x,y):
	n=rol_128(x,2) ^ y
	n=add_128(n,C)
	n=rol_128(n,87)
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

def get_content_sizes():
	with open(DIR+"header.bin","rb") as f:
		f.seek(0x48)
		temp=f.read(0x2C)
	for i in range(11):
		offset=i*4
		content_sizelist[i]=bytes2int(temp[offset:offset+4])
		if(content_sizelist[i]==0xB34):
			content_sizelist[i]=0xB40

def get_content_block(buff):
	global cmac_keyx
	hash=hashlib.sha256(buff).digest()
	key = int16bytes(normalkey(cmac_keyx, keyy))
	cipher = CMAC.new(key, ciphermod=AES)
	result = cipher.update(hash)
	return result.digest() + b''.join(bytechr(random.randint(0,255)) for _ in range(16))

def sign_footer():
	print("-----------Handing off to ctr-dsiwaretool...\n")
	os.system(r"resources\ctr-dsiwaretool.exe "+DIR+"footer.bin resources/ctcert.bin --write")
	print("\n-----------Returning to TADpole...")
	
def fix_hashes_and_sizes():
	sizes=[0]*11
	hashes=[""]*13
	footer_namelist=["banner.bin","header.bin"]+content_namelist
	for i in range(11):
		if(os.path.exists(DIR+content_namelist[i])):
			sizes[i] = os.path.getsize(DIR+content_namelist[i])
		else:
			sizes[i] = 0
	sizes[0]=0xB34
	for i in range(13):
		if(os.path.exists(DIR+footer_namelist[i])):
			with open(DIR+footer_namelist[i],"rb") as f:
				hashes[i] = hashlib.sha256(f.read()).digest()
		else:
			hashes[i] = int16bytes(0)
			
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

print("TADpole by zoogie")
print("Usage: python TADpole.py <dsiware export> <dump or rebuild (d or r)>\n")

wkdir=sys.argv[1].replace(".bin","/",1)
if(wkdir.count('.')==0 and wkdir.count('/')==1):
	DIR=wkdir
print("Using workdir: "+DIR)

if(sys.argv[2]=="dump" or sys.argv[2]=="d"):
	print("Dumping sections...")
	print("Offset    Size      Filename")

	if not os.path.exists(DIR):
		os.makedirs(DIR)
	get_keyy()
	dump_section(BANNER, BANNER_SIZE, DIR+"banner.bin")
	dump_section(HEADER, HEADER_SIZE, DIR+"header.bin")
	dump_section(FOOTER, FOOTER_SIZE, DIR+"footer.bin")
	get_content_sizes()
	tad_offset=TMD
	for i in range(11):
		if(content_sizelist[i]):
			dump_section(tad_offset, content_sizelist[i], DIR+content_namelist[i])
			tad_offset+=(content_sizelist[i]+BM)
	#get_cmac(DIR+"banner.bin")
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
