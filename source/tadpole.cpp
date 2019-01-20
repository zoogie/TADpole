#include <cstring>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "crypto.h"
#include "tadpole.h"
#include "ec.h"
#include "types.h"

void getSection(u8 *dsiware_pointer, u32 section_size, u8 *key, u8 *output) {
        decryptAES(dsiware_pointer, section_size, key, (dsiware_pointer + section_size + 0x10), output);
}

void placeSection(u8 *dsiware_pointer, u8 *section, u32 section_size, u8 *key, u8 *key_cmac) {
        u8 allzero[0x10]= {0};

        encryptAES(section, section_size, key, allzero, dsiware_pointer);

        u8 section_hash[0x20] = {0};
        calculateSha256(section, section_size, section_hash);
        u8 section_cmac[0x20] = {0};
        calculateCMAC(section_hash, 0x20, key_cmac, section_cmac);

        memcpy((dsiware_pointer + section_size), section_cmac, 0x10);
        memset((dsiware_pointer + section_size + 0x10), 0, 0x10);
}

static void elt_print(const char *name, u8 *a)
{
	u32 i;

	printf("%s = ", name);

	for (i = 0; i < 30; i++)
		printf("%02x", a[i]);

	printf("\n");
}

Result doSigning(u8 *ctcert_bin, footer_t *footer) {
	Result res;
	u8 ct_priv[0x1E], ap_priv[0x1E], tmp_pub[0x3C], tmp_hash[0x20];
	memset(ap_priv, 0, 0x1E);
	ecc_cert_t ct_cert, ap_cert;
	ap_priv[0x1D]=1;

	printf("loading keys from ctcert.bin...\n");
	memcpy(&ct_cert, ctcert_bin, 0x180);
	memcpy(ct_priv, (ctcert_bin + 0x180), 0x1E);
	
	ec_priv_to_pub(ct_priv, tmp_pub);
	if (memcmp(tmp_pub, &ct_cert.pubkey, sizeof(tmp_pub)) != 0) {
		printf("error: ecc priv key does not correspond to the cert\n");
		return -1;
	}

	printf("using zeroed AP privkey to generate AP cert...\n");
	memset(&ap_cert, 0, sizeof(ap_cert));
	memcpy(&ap_cert.key_id, &footer->ap.key_id, 0x40);

	snprintf(ap_cert.issuer, sizeof(ap_cert.issuer), "%s-%s", ct_cert.issuer, ct_cert.key_id);

	ap_cert.key_type = 0x02000000; // key type
	ec_priv_to_pub(ap_priv, ap_cert.pubkey.r);// pub key
	ap_cert.sig.type = 0x05000100;// sig
	
	srand(time(0));
	int check=rand();
	printf("%08X\n",check); 
	int sanity=100;
	bool randsig=false;
	
	do{
		printf("signing ap...\n"); // actually sign it
		calculateSha256((u8*)ap_cert.issuer, 0x100, tmp_hash);
		//calculateSha256((u8*)&check, 4, tmp_hash);
		res = generate_ecdsa(ap_cert.sig.val.r, ap_cert.sig.val.s, ct_priv, tmp_hash, randsig);
		if (res < 0) {
			printf("error: problem signing AP\n");
		}
		printf("re-verifying ap sig...      ");
		calculateSha256((u8*)ap_cert.issuer, sizeof(ecc_cert_t)-sizeof(ap_cert.sig), tmp_hash);
		//calculateSha256((u8*)&check, 4, tmp_hash);
		res = check_ecdsa(ct_cert.pubkey.r, ap_cert.sig.val.r, ap_cert.sig.val.s, tmp_hash);
		if (res == 1) {
			printf("GOOD!\n");
		} else {
			printf("BAD\n");
			randsig=true;
		}
		elt_print("R", ap_cert.sig.val.r);
		elt_print("S", ap_cert.sig.val.s);
		elt_print("H", tmp_hash);
		sanity--;
	} while(res !=1 && sanity >=0);
	
	sanity=100;
	randsig=false;

	do{
		printf("signing footer...\n");
		calculateSha256((u8*)footer, 0x1A0, tmp_hash);
		//calculateSha256((u8*)&check, 4, tmp_hash);
		res = generate_ecdsa(footer->sig.r, footer->sig.s, ap_priv, tmp_hash, randsig);
		if (res < 0) {
			printf("error: problem signing footer\n");
		}
		printf("re-verifying footer sig...  ");
		calculateSha256((u8*)footer, 0x1A0, tmp_hash);
		//calculateSha256((u8*)&check, 4, tmp_hash);
		res = check_ecdsa(ap_cert.pubkey.r, footer->sig.r, footer->sig.s, tmp_hash);
		if (res == 1) {
			printf("GOOD!\n");
		} else {
			printf("BAD\n");
			randsig=true;
		}
		elt_print("R", ap_cert.sig.val.r);
		elt_print("S", ap_cert.sig.val.s);
		elt_print("H", tmp_hash);
		sanity--;
	} while(res !=1 && sanity >=0);

	
	memcpy(&footer->ap, &ap_cert, 0x180);
	memcpy(&footer->ct, &ct_cert, 0x180);
	
	printf("done signing\n");

	return 0;
}
