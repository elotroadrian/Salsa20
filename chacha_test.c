
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include "ecrypt-sync.h"
#include "ecrypt-portable.h"
#include "sodium.h"


#define CHUNKSIZE 1024
#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d)(		\
	b ^= ROTL(a + d, 7),	\
	c ^= ROTL(b + a, 9),	\
	d ^= ROTL(c + b,13),	\
	a ^= ROTL(d + c,18))
#define ROUNDS 20

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void salsa20_block(uint32_t out[16], uint32_t const in[16]);
void ECRYPT_keysetup(ECRYPT_ctx* x, const uint8_t* k, uint32_t kbits, uint32_t ivbits);
void ECRYPT_ivsetup(ECRYPT_ctx* x, const uint8_t* iv);
void ECRYPT_encrypt_bytes(ECRYPT_ctx* x, const uint8_t* m, uint8_t* c, uint32_t bytes);
void ECRYPT_decrypt_bytes(ECRYPT_ctx* x, const uint8_t* c, uint8_t* m, uint32_t bytes);
void ECRYPT_keystream_bytes(ECRYPT_ctx* x, uint8_t* stream, uint32_t bytes);
void ECRYPT_init();


int main(void)
{
    sodium_init();
    uint8_t test = (randombytes_random());

    const uint8_t input[CHUNKSIZE] = "TEST TEXT TO BE ENCRYPTED"; 
    ECRYPT_ctx ctx; 
    uint8_t* key, * IV, * ciphertext, * result; 

    key = &test; // generating random key with libsodium
    //key = (uint8_t*)calloc((size_t)ECRYPT_MAXKEYSIZE / 8, sizeof(uint8_t)); //Memory allocation of key
    IV = (uint8_t*)calloc((size_t)ECRYPT_MAXIVSIZE / 8, sizeof(uint8_t)); //Memory allocation of IV

   
    printf("\nUsing random %d bit key with value of %d and %d bit IV:\n\nEncrypting: [%s]\n\nResult:\n ", ECRYPT_MAXKEYSIZE, test, ECRYPT_MAXIVSIZE, input);

    ECRYPT_init();
    ECRYPT_keysetup(&ctx, key, ECRYPT_MAXKEYSIZE, ECRYPT_MAXIVSIZE);
    ECRYPT_ivsetup(&ctx, IV);

    ciphertext = (uint8_t*)calloc((size_t)CHUNKSIZE, sizeof(uint8_t));

    ECRYPT_encrypt_bytes(&ctx, input, ciphertext, CHUNKSIZE);

    result = (uint8_t*)calloc((size_t)CHUNKSIZE, sizeof(uint8_t));
    printf("\nEncrypted text %s\n", ciphertext);

    ECRYPT_ivsetup(&ctx, IV);
    ECRYPT_decrypt_bytes(&ctx, ciphertext, result, CHUNKSIZE);
    printf("\nDecrypting back: [%s]\n", result);

    return 0;
}

/*******************************************************************************************************/
/*CHACHA20*/

//#define QUARTERROUND(a,b,c,d) \
//  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
//  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
//  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
//  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);
//
//static void salsa20_wordtobyte(uint8_t output[64],const u32 input[16])
//{
//  u32 x[16];
//  int i;
//
//  for (i = 0;i < 16;++i) x[i] = input[i];
//  for (i = 8;i > 0;i -= 2) {
//    QUARTERROUND( 0, 4, 8,12)
//    QUARTERROUND( 1, 5, 9,13)
//    QUARTERROUND( 2, 6,10,14)
//    QUARTERROUND( 3, 7,11,15)
//    QUARTERROUND( 0, 5,10,15)
//    QUARTERROUND( 1, 6,11,12)
//    QUARTERROUND( 2, 7, 8,13)
//    QUARTERROUND( 3, 4, 9,14)
//  }
//  for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]);
//  for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
//}


/*******************************************************************************************************/
/*SALSA20*/

void salsa20_block(uint32_t out[16], uint32_t const in[16])
{
    int i;
    uint32_t x[16];

    for (i = 0; i < 16; ++i)
        x[i] = in[i];
    // 10 loops × 2 rounds/loop = 20 rounds
    for (i = 0; i < ROUNDS; i += 2) {
        // Odd round
        QR(x[0], x[4], x[8], x[12]);	// column 1
        QR(x[5], x[9], x[13], x[1]);	// column 2
        QR(x[10], x[14], x[2], x[6]);	// column 3
        QR(x[15], x[3], x[7], x[11]);	// column 4
        // Even round
        QR(x[0], x[1], x[2], x[3]);	// row 1
        QR(x[5], x[6], x[7], x[4]);	// row 2
        QR(x[10], x[11], x[8], x[9]);	// row 3
        QR(x[15], x[12], x[13], x[14]);	// row 4
    }
    for (i = 0; i < 16; ++i)
        out[i] = x[i] + in[i];
}

/*******************************************************************************************************/


void ECRYPT_keysetup(ECRYPT_ctx* x, const uint8_t* k, uint32_t kbits, uint32_t ivbits)
{
    const char* constants;

    x->input[4] = U8TO32_LITTLE(k + 0);
    x->input[5] = U8TO32_LITTLE(k + 4);
    x->input[6] = U8TO32_LITTLE(k + 8);
    x->input[7] = U8TO32_LITTLE(k + 12);
    if (kbits == 256) { /* recommended */
        k += 16;
        constants = sigma;
    }
    else { /* kbits == 128 */
        constants = tau;
    }
    x->input[8] = U8TO32_LITTLE(k + 0);
    x->input[9] = U8TO32_LITTLE(k + 4);
    x->input[10] = U8TO32_LITTLE(k + 8);
    x->input[11] = U8TO32_LITTLE(k + 12);
    x->input[0] = U8TO32_LITTLE(constants + 0);
    x->input[1] = U8TO32_LITTLE(constants + 4);
    x->input[2] = U8TO32_LITTLE(constants + 8);
    x->input[3] = U8TO32_LITTLE(constants + 12);
}

void ECRYPT_ivsetup(ECRYPT_ctx* x, const uint8_t* iv)
{
    x->input[12] = 0;
    x->input[13] = 0;
    x->input[14] = U8TO32_LITTLE(iv + 0);
    x->input[15] = U8TO32_LITTLE(iv + 4);
}

void ECRYPT_encrypt_bytes(ECRYPT_ctx* x, const uint8_t* m, uint8_t* c, uint32_t bytes)
{
    uint32_t output[64];
    uint32_t i;

    if (!bytes) return;
    for (;;) {
        salsa20_block(output, x->input);
        x->input[12] = PLUSONE(x->input[12]);
        if (!x->input[12]) {
            x->input[13] = PLUSONE(x->input[13]);
            /* stopping at 2^70 bytes per nonce is user's responsibility */
        }
        if (bytes <= 64) {
            for (i = 0; i < bytes; ++i) c[i] = m[i] ^ output[i];
            return;
        }
        for (i = 0; i < 64; ++i) c[i] = m[i] ^ output[i];
        bytes -= 64;
        c += 64;
        m += 64;
    }
}


void ECRYPT_decrypt_bytes(ECRYPT_ctx* x, const uint8_t* c, uint8_t* m, uint32_t bytes)
{
    ECRYPT_encrypt_bytes(x, c, m, bytes);
}

void ECRYPT_keystream_bytes(ECRYPT_ctx* x, uint8_t* stream, uint32_t bytes)
{
    uint32_t i;
    for (i = 0; i < bytes; ++i) stream[i] = 0;
    ECRYPT_encrypt_bytes(x, stream, stream, bytes);
}

void ECRYPT_init() 
{

}
