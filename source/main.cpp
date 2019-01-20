#include <cstring>
#include <string>
#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "crypto.h"
#include "tadpole.h"
#include "types.h"
#include "hash_stash.h"

void error(const char *errormsg, const char *filename, bool fatal) {
	printf("%s:%s %s\nHit Enter to close\n", fatal ? "ERROR":"WARNING", errormsg, filename);
	getchar();
	if(fatal) exit(1); 
}

u8 *readAllBytes(const char *filename, u32 &filelen) {
	FILE *fileptr = fopen(filename, "rb");
	if (fileptr == NULL) {
		error("Failed to open ", filename, true);
	}
	
	fseek(fileptr, 0, SEEK_END);
	filelen = ftell(fileptr);
	rewind(fileptr);
	
	if(filelen > 0x4000000) filelen=0x4000000; //keep dsiware buffer reasonable

	u8 *buffer = (u8*)malloc(filelen);

	fread(buffer, filelen, 1, fileptr);
	fclose(fileptr);

	return buffer;
}

void writeAllBytes(const char *filename, u8 *filedata, u32 filelen) {
	FILE *fileptr = fopen(filename, "wb");
	fwrite(filedata, 1, filelen, fileptr);
	fclose(fileptr);
}

void dumpMsedData(u8 *msed){
	u32 keyy[4]={0};
	int mdata[3]={33,33,33};
	memcpy(keyy, msed+0x110, 0x10);
	mdata[0]=(keyy[0]&0xFFFFFF00) | 0x80;
	keyy[3]&=0x7FFFFFFF;
	
	mdata[1]=(keyy[0]/5) - keyy[3];
	if(keyy[1]==2) mdata[2]=3;
	else if(keyy[1]==0) mdata[2]=2;
	
	writeAllBytes("msed_data.bin", (u8*)mdata, 12);
}

u16 crc16(u8 *data, u32 N) //https://modbus.control.com/thread/1381836105#1381859471
{
    u16    reg, bit, yy, flag;

    yy = 0;
    reg = 0xffff;

    while( N-- > 0 ) 
    {
	reg = reg ^ data[yy];
	yy = yy + 1;

	for ( bit = 0; bit <= 7; bit++ )
	{
	    flag = reg & 0x0001;
	    reg  = reg >> 1;
	    if ( flag == 1 )
	        reg = reg ^ 0xa001;
	}
    }
    return ( reg );
}

void fixcrc16(u16 *checksum, u8 *message, u32 len){
	u16 original=*checksum;
	u16 calculated=crc16(message, len);
	printf("orig:%04X calc:%04X  ", original, calculated);
	if(original != calculated){
		*checksum=calculated;
		printf("fixed\n");
		return;
	}
	printf("good\n");
}

void dumpTad(char *filename, char *dname) {
	u8 *dsiware, *wbuff, *contents, *banner, *header, *footer, *movable;
	u32 dsiware_size, movable_size, banner_size=0x4000, header_size=0xF0, footer_size=0x4E0; //the 3ds currently uses the 11 content sections version of dsiware exports. this is all we should encounter.
	u32 banner_off=0, header_off=0x4020, footer_off=0x4130, tmd_off=0x4630;  //0x4000+0x20+0xF0+0x20+0x4E0+0x20
	u32 content_size[11]={0};
	const char *content_namelist[]={"tmd","srl.nds","2.bin","3.bin","4.bin","5.bin","6.bin","7.bin","8.bin","public.sav","banner.sav"};
	u32 content_off=tmd_off;
	u32 checked_size=0;
	//u8 header_hash[0x20] = {0}, srl_hash[0x20] = {0}, tmp_hash[0x20] = {0}, tmd_hash[0x20]={0}, banner_hash[0x20]={0};
	u8 normalKey[0x10] = {0}, normalKey_CMAC[0x10] = {0};
	header_t header_out;
	memset(&header_out, 0, 0xF0);

	printf("Reading %s\n", filename);
	dsiware = readAllBytes(filename, dsiware_size);
	if (dsiware_size > 0x4000000) {
		error("Provided dsiware seems to be way too large!","", true);
	}
	
	printf("Reading resources/movable.sed\n");
	movable = readAllBytes("resources/movable.sed", movable_size);
	if (movable_size != 320 && movable_size != 288) {
		error("Provided movable.sed is not 320 or 288 bytes of size","", true);
	}
	
	printf("Dumping msed_data.bin\n");
	dumpMsedData(movable);

	printf("Scrambling keys\n");
	keyScrambler((movable + 0x110), false, normalKey);
	keyScrambler((movable + 0x110), true, normalKey_CMAC);
	
	wbuff=(u8*)malloc(tmd_off);
	
	banner=wbuff;
	header=wbuff+header_off;
	footer=wbuff+footer_off;
	
	// === HEADER ===
	printf("Decrypting header\n");
	getSection((dsiware + header_off), header_size, normalKey, header);
	
	if (memcmp("3FDT", header, 4)) {
		error("Decryption failed","", true);
	}
	
	memcpy(content_size, header+0x48, 11*4);
	content_size[0]+=0xC; //tmd padding adjust
	
	printf("Verifying input dsiware size\n");
	for(int i=0;i<11;i++){
		if(content_size[i]){
			checked_size+=(content_size[i]+0x20);
		}
	}
	checked_size+=tmd_off;
	
	
	printf("checked %08X actual %08X\n",checked_size, dsiware_size);
	if(checked_size != dsiware_size){  
		error("Input dsiware size does not agree with its header!","", true);
	}
	
	getSection((dsiware + banner_off), banner_size, normalKey, banner);
	getSection((dsiware + footer_off), footer_size, normalKey, footer);

	chdir(dname);
	printf("Dumping %s/banner.bin\n", dname);
	writeAllBytes("banner.bin", banner, banner_size);
	printf("Dumping %s/header.bin\n", dname);
	writeAllBytes("header.bin", header, header_size);
	printf("Dumping %s/footer.bin\n", dname);
	writeAllBytes("footer.bin", footer, footer_size);
	
	contents=(u8*)malloc(dsiware_size);
	
	for(int i=0;i<11;i++){
		if(content_size[i]){
			printf("Dumping %s/%s\n", dname, content_namelist[i]);
			getSection((dsiware + content_off), content_size[i], normalKey, contents);
			writeAllBytes(content_namelist[i], contents, content_size[i]);
			content_off+=0x20;
		}
		content_off+=content_size[i];
	}

	printf("Done!\n");
	
	printf("Cleaning up\n");
	free(contents);
	free(dsiware);
	free(wbuff);
	free(movable);
	printf("Done!\n");
}

void rebuildTad(char *filename, char *dname) {
	u8 *dsiware, *ctcert, *banner, *header, *footer, *movable;
	u32 ctcert_size, header_size, footer_size, movable_size, banner_size;
	u8 banner_hash[0x20]={0}, header_hash[0x20] = {0};
	u8 content_hash[11][0x20]={0};
	u32 banner_off=0, header_off=0x4020, footer_off=0x4130, tmd_off=0x4630;  //0x4000+0x20+0xF0+0x20+0x4E0+0x20
	u32 content_off=tmd_off;
	u32 checked_size=tmd_off;
	u32 content_size[11]={0};
	const char *content_namelist[]={"tmd","srl.nds","2.bin","3.bin","4.bin","5.bin","6.bin","7.bin","8.bin","public.sav","banner.sav"};
	u8 *contents[11];
	u8 normalKey[0x10] = {0}, normalKey_CMAC[0x10] = {0};
	char outname[64]={0};
	memset(content_hash, 0, 11*0x20);
	
	printf("Reading resources/movable.sed\n");
	movable = readAllBytes("resources/movable.sed", movable_size);
	if (movable_size != 320 && movable_size != 288) {
		error("Provided movable.sed is not 320 or 288 bytes of size","", true);
	}
	
	printf("Reading resources/ctcert.bin\n");
	ctcert = readAllBytes("resources/ctcert.bin", ctcert_size);
	
	chdir(dname);
	
	printf("Reading %s/banner.bin\n", dname);
	banner = readAllBytes("banner.bin", banner_size);
	
    printf("Reading %s/header.bin\n", dname);
	header = readAllBytes("header.bin", header_size);
	
	printf("Reading %s/footer.bin\n", dname);
	footer = readAllBytes("footer.bin", footer_size);
	
	printf("Fixing banner crc16s\n");
	fixcrc16((u16*)(banner+0x2), banner+0x20, 0x820);
	fixcrc16((u16*)(banner+0x4), banner+0x20, 0x920);
	fixcrc16((u16*)(banner+0x6), banner+0x20, 0xA20);
	fixcrc16((u16*)(banner+0x8), banner+0x1240, 0x1180);
	
	printf("Scrambling keys\n");
	keyScrambler((movable + 0x110), false, normalKey);
	keyScrambler((movable + 0x110), true, normalKey_CMAC);
		
	printf("Getting content section sizes and hashes\n");
	for(int i=0;i<11;i++){
		if( access( content_namelist[i], F_OK ) != -1 ) {
			if      (i==1 && access( "srl.nds.inject", F_OK ) != -1 )    contents[i] = readAllBytes("srl.nds.inject", content_size[i]);
			else if (i==9 && access( "public.sav.inject", F_OK ) != -1 ) contents[i] = readAllBytes("public.sav.inject", content_size[i]);
			else                                                         contents[i] = readAllBytes(content_namelist[i], content_size[i]);
			
			checked_size+=(content_size[i]+0x20);
			calculateSha256(contents[i],content_size[i], content_hash[i]);
		}
	}
	
	if(*(u32*)(header+0x48+4) < content_size[1]){
		*(u32*)(header+0x40)=(content_size[1]+0x20000)&0xFFFF8000;
	}
	
	content_size[0]-=0xC;
	memcpy(header+0x48, content_size, 11*4);
	
	printf("Getting banner and header hashes\n");
	calculateSha256(banner, banner_size, banner_hash);
	calculateSha256(header, header_size, header_hash);
	
	printf("Writing final footer hashes\n");
	
	memset(footer, 0, 13*0x20);
	memcpy(footer, banner_hash, 0x20);
	memcpy(footer+0x20, header_hash, 0x20);
	
	for(int i=0;i<11;i++){
		if(content_size[i]){
			memcpy(footer+0x40+(i*0x20), content_hash[i], 0x20);
		}
	}
	
	printf("Signing the footer!\n");
	Result res = doSigning(ctcert, (footer_t*)footer);
	if (res < 0) {
		error("Signing failed","", true);
	}
	
	printf("Copying all sections to output buffer\n");
	
	dsiware=(u8*)malloc(checked_size);
	printf("Writing banner\n"); placeSection((dsiware + banner_off), banner, banner_size, normalKey, normalKey_CMAC);
	printf("Writing header\n"); placeSection((dsiware + header_off), header, header_size, normalKey, normalKey_CMAC);
	printf("Writing TMD\n");    placeSection((dsiware + footer_off), footer, footer_size, normalKey, normalKey_CMAC);
	
	content_size[0]+=0xC;
	for(int i=0;i<11;i++){
		if(content_size[i]){
			printf("Writing %s\n", content_namelist[i]);
			placeSection((dsiware + content_off), contents[i], content_size[i], normalKey, normalKey_CMAC);
			content_off+=(content_size[i]+0x20);
			free(contents[i]);
		}
	}
	
	snprintf(outname, 32, "../%s.bin.patched", dname);

	printf("Writing %s.bin.patched\n", dname);
	writeAllBytes(outname, dsiware, checked_size);
	printf("Done!\n");
	
	printf("Cleaning up\n");
	free(banner);
	free(header);
	free(footer);
	free(dsiware);
	free(movable);
	free(ctcert);
	printf("Done!\n");
}

void usage(){
	printf("TADpole <8-digitHex.bin(dsiware export)> <d|r>\n");
	printf("ex. TADpole 484E4441.bin d  (this dumps the dsiware export)\n");
	printf("ex. TADpole 484E4441.bin r  (this rebuilds the dsiware export)\n");
}

int ishex(char *in, u32 size){
	const char hex[]="0123456789ABCDEFabcdef";
	u32 match=0;
	u32 i,c;
	for(i=0;i<size;i++){
		for(c=0;c<22;c++){
			if(in[i]==hex[c]){
				match=1;
				break;
			}
		}
		if(match==0) return 1;
		match=0;
		if(c>15) in[i]-=0x20; //toupper()
			//printf("%d\n",(int)c);
	}
	
	return 0;
}

int main(int argc, char* argv[]) {
	char dname[64]={0};
	int len=strlen(argv[1]);
	
	if(len<8 || argc!=3){
		usage();
		return 1;
	}
	
	if(memcmp(argv[2], "d", 1) && memcmp(argv[2], "r", 1) && memcmp(argv[2], "D", 1) && memcmp(argv[2], "R", 1)){
		usage();
		return 1;
	}
	
	memcpy(dname, argv[1], 8);
	//printf("hex check %d %s\n", len,dname);
	
	if(ishex(dname,8)){
		usage();
		return 1;
	}
	
	mkdir(dname);
	
	printf("|TADpole by zoogie|\n");
	printf("|_______v2.0______|\n");

	if     (!memcmp(argv[2], "d", 1) || !memcmp(argv[2], "D", 1))    dumpTad(argv[1], dname); 
	else if(!memcmp(argv[2], "r", 1) || !memcmp(argv[2], "R", 1)) rebuildTad(argv[1], dname); 
	printf("\nJob completed\n");
	
	return 0;
}