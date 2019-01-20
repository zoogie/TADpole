
#define SIZE_FOOTER 0x4E0
#define SIZE_CTCERTBIN 0x19E

typedef u8 sha256_hash[0x20];

typedef struct ecc_point_t
{
	uint8_t r[0x1e];
	uint8_t s[0x1e];
} __attribute__((packed)) ecc_point_t;

typedef struct ecc_cert_t
{
	struct {
		uint32_t type;
		ecc_point_t val;
		uint8_t padding[0x40];
	} sig;
	char issuer[0x40];
	uint32_t key_type;
	char key_id[0x40];
	uint32_t unk;
	ecc_point_t pubkey;
	uint8_t padding2[0x3c];
} __attribute__((packed)) ecc_cert_t;

typedef struct footer_t
{
	sha256_hash banner_hash;
	sha256_hash hdr_hash;
	sha256_hash tmd_hash;
	sha256_hash content_hash[8];
	sha256_hash savedata_hash;
	sha256_hash bannersav_hash;
	ecc_point_t sig;
	ecc_cert_t ap;
	ecc_cert_t ct;
} footer_t;

typedef struct header_t
{
	u32 magic;
	u16 group_id;
	u16 version;
	u8 sha256_ivs[0x20];
	u8 aes_zeroblock[0x10];
	u64 tid;
	u64 installed_size;
	u32 content[11];
	u8 padding[0x7C]; //not totally padding, but no idea what some values in the middle are
	
	
} header_t;

Result doSigning(u8 *ctcert_bin, footer_t *footer);
void getSection(u8 *dsiware_pointer, u32 section_size, u8 *key, u8 *output);
void placeSection(u8 *dsiware_pointer, u8 *section, u32 section_size, u8 *key, u8 *key_cmac);