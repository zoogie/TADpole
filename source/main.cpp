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

#define CONTENT_MAX 11
#define OFFSET_BANNER 0
#define OFFSET_HEADER 0x4020
#define OFFSET_FOOTER 0x4130
#define OFFSET_TMD 0x4630
#define SIZE_BANNER 0x4000
#define SIZE_HEADER 0xF0
#define SIZE_FOOTER 0x4E0

const char *content_namelist[]={"tmd","srl.nds","2.bin","3.bin","4.bin","5.bin","6.bin","7.bin","8.bin","public.sav","banner.sav"};
u8 *readAllBytes(const char *filename, u32 &filelen);
void writeAllBytes(const char *filename, u8 *filedata, u32 filelen);
void error(const char *errormsg, const char *filename, bool fatal);

u8 normalKey[0x10]={0};
u8 normalKey_CMAC[0x10]={0};

//u8 *ctcert;
extern u8 ctcert[];
extern int ctcert_size;

class TAD {

	public:
	u8 banner[SIZE_BANNER];
	u8 header[SIZE_HEADER];
	u8 *contents[CONTENT_MAX];
	u8 footer[SIZE_FOOTER];
	u32 dsiware_size;
	~TAD() {
		u32 content_size[11]={0};
		memcpy(content_size, header+0x48, 11*4);
		content_size[0]+=0xC; //tmd padding adjust
		
		//printf("Deallocating memory\n");
		for(int i=0;i<11;i++){
			if(content_size[i]){
				free(contents[i]);
			}
		}
	}
	TAD(char *filename) {
		u8 *dsiware;
		u32 content_size[11]={0};
		u32 content_off=OFFSET_TMD;
		u32 checked_size=0;
		memset(header,0,SIZE_HEADER);
		memset(banner,0,SIZE_BANNER);
		memset(footer,0,SIZE_FOOTER);
		printf("Reading %s\n", filename);

		dsiware = readAllBytes(filename, dsiware_size);
		if (dsiware_size > 0x4000000) {
			error("Provided dsiware seems to be way too large!\nsize is > 4MB","", true);
		}
		
		getSection((dsiware + OFFSET_HEADER), SIZE_HEADER, normalKey, header);
		
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
		checked_size+=OFFSET_TMD;
		
		
		if(checked_size != dsiware_size){  
			error("Input dsiware size does not agree with its header!","", true);
		}
		
		getSection((dsiware + OFFSET_BANNER), SIZE_BANNER, normalKey, banner);
		getSection((dsiware + OFFSET_FOOTER), SIZE_FOOTER, normalKey, footer);

		
		for(int i=0;i<11;i++){
			if(content_size[i]){
				contents[i]=(u8*)calloc(1,content_size[i]);
				getSection((dsiware + content_off), content_size[i], normalKey, contents[i]);
				content_off+=0x20;
			}
			content_off+=content_size[i];
		}

		printf("Done!\n");
		
		free(dsiware);

	}

	void dumpModifiedTad(uint64_t uTID) {
		u8 *dsiware;
		u8 header_hash[0x20] = {0};
		u32 content_off=OFFSET_TMD;
		u32 content_size[11]={0};
		char outname[64]={0};

		snprintf(outname, 32, "%08x.bin", (u32)(uTID & 0xFFFFFFFF));

		for (int offset=0x38;offset<0x40;++offset) {
			header[offset] = uTID&0xFF;
			uTID = uTID >> 8;
		}
		calculateSha256(header, SIZE_HEADER, header_hash);
		
		//printf("Writing final footer hashes\n");
		
		memcpy(footer+0x20, header_hash, 0x20);
		//printf("Signing the footer!\n");
		Result res = doSigning(ctcert, (footer_t*)footer);
		if (res < 0) {
			error("Signing failed","", true);
		}
		
		//printf("Copying all sections to output buffer\n");
		
		dsiware=(u8*)calloc(1,dsiware_size);

		//printf("Writing banner\n"); 
		placeSection((dsiware + OFFSET_BANNER), banner, SIZE_BANNER, normalKey, normalKey_CMAC);
		//printf("Writing header\n"); 
		placeSection((dsiware + OFFSET_HEADER), header, SIZE_HEADER, normalKey, normalKey_CMAC);
		//printf("Writing TMD\n");    
		placeSection((dsiware + OFFSET_FOOTER), footer, SIZE_FOOTER, normalKey, normalKey_CMAC);

		memcpy(content_size, header+0x48, 11*4);
		content_size[0]+=0xC;
		for(int i=0;i<11;i++){
			if(content_size[i]){
				//printf("Writing %s: %d bytes\n", content_namelist[i], content_size[i]);
				placeSection((dsiware + content_off), contents[i], content_size[i], normalKey, normalKey_CMAC);
				content_off+=(content_size[i]+0x20);
			}
		}

		printf("Writing file %s\t", outname);
		writeAllBytes(outname, dsiware, dsiware_size);
		printf("Done!\n");
		
		//printf("Cleaning up\n");
		free(dsiware);
		//printf("Done!\n");
	}


};


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

	u8 *buffer = (u8*)calloc(1,filelen);

	fread(buffer, filelen, 1, fileptr);
	fclose(fileptr);

	return buffer;
}

void writeAllBytes(const char *filename, u8 *filedata, u32 filelen) {
	FILE *fileptr = fopen(filename, "wb");
	fwrite(filedata, 1, filelen, fileptr);
	fclose(fileptr);
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
	//printf("orig:%04X calc:%04X  ", original, calculated);
	if(original != calculated){
		*checksum=calculated;
		printf("fixed\n");
		return;
	}
	//printf("good\n");
}


void usage(){
	printf("TWLFix input.bin [TargetTID]\n");
	printf("ex. TADpole 484E4441.bin\n");
	printf("ex. TADpole 484E4441.bin 0x0004013800001234\n");
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

	if(argc<2){
		usage();
		return 1;
	}

	u64 uTargetTID=0;
	if (argc > 2) {
		char *pEnd;
		uTargetTID = strtoull (argv[2], &pEnd, 16);
	}
	printf("\n");
	printf("#####################\n");
	printf("# TADpole by zoogie #\n");
	printf("# TWLFix Mod        #\n");
	printf("#        v2.0       #\n");
	printf("#####################\n\n");
	//u32 ctcert_size=0;
	//printf("Reading ctcert.bin\n");
	/*ctcert = readAllBytes("ctcert.bin", ctcert_size);*/
	if (ctcert_size != 414 ) {
		error("ctcert.bin size invalid.","",true);
	}
	//printf("ctcert %d\n",ctcert_size);
	// === MOVABLE/KEY ===
	u32 movable_size=0;
	//printf("Reading movable.sed\n");
	u8 *movable = readAllBytes("movable.sed", movable_size);
	if (movable_size != 320 && movable_size != 288) {
		error("Provided movable.sed is not 320 or 288 bytes of size","", true);
	}
	keyScrambler((movable + 0x110), false, normalKey);
	keyScrambler((movable + 0x110), true, normalKey_CMAC);
	free(movable);


	TAD DSi(argv[1]);
	if (uTargetTID > 0) {
		printf("Target ID: %016llx\n",uTargetTID);
		DSi.dumpModifiedTad(uTargetTID);
	}else{
		printf("No Target ID provided, dumping 4 default.\n");
		DSi.dumpModifiedTad(0x0004013800000102);
		DSi.dumpModifiedTad(0x0004013820000102);
		DSi.dumpModifiedTad(0x0004800f484e4841);
		DSi.dumpModifiedTad(0x0004800f484e4C41);
	}
	printf("\nJob completed\n");
	//printf("Cleaning up\n");
	//free(ctcert);
	//printf("Program complete\n\n");
	printf("Press Enter to exit...");
	std::cin.ignore();
	return 0;
}
