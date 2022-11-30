#include "crypto_aead.h"

int crypto_verify_16(const unsigned char *x,const unsigned char *y)
{
  unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
  F(0)
  F(1)
  F(2)
  F(3)
  F(4)
  F(5)
  F(6)
  F(7)
  F(8)
  F(9)
  F(10)
  F(11)
  F(12)
  F(13)
  F(14)
  F(15)
  return (1 & ((differentbits - 1) >> 8)) - 1;
}



static unsigned char multiply(unsigned int c,unsigned int d)
{
  unsigned char f[8];
  unsigned char g[8];
  unsigned char h[15];
  unsigned char result;
  int i;
  int j;

  for (i = 0;i < 8;++i) f[i] = 1 & (c >> i);
  for (i = 0;i < 8;++i) g[i] = 1 & (d >> i);
  for (i = 0;i < 15;++i) h[i] = 0;
  for (i = 0;i < 8;++i)
    for (j = 0;j < 8;++j) h[i + j] ^= f[i] & g[j];

  for (i = 6;i >= 0;--i) {
    h[i + 0] ^= h[i + 8];
    h[i + 1] ^= h[i + 8];
    h[i + 3] ^= h[i + 8];
    h[i + 4] ^= h[i + 8];
    h[i + 8] ^= h[i + 8];
  }

  result = 0;
  for (i = 0;i < 8;++i) result |= h[i] << i;
  return result;
}

static unsigned char square(unsigned char c)
{
  return multiply(c,c);
}

static unsigned char xtime(unsigned char c)
{
  return multiply(c,2);
}

static unsigned char bytesub(unsigned char c)
{
  unsigned char c3 = multiply(square(c),c);
  unsigned char c7 = multiply(square(c3),c);
  unsigned char c63 = multiply(square(square(square(c7))),c7);
  unsigned char c127 = multiply(square(c63),c);
  unsigned char c254 = square(c127);
  unsigned char f[8];
  unsigned char h[8];
  unsigned char result;
  int i;

  for (i = 0;i < 8;++i) f[i] = 1 & (c254 >> i);
  h[0] = f[0] ^ f[4] ^ f[5] ^ f[6] ^ f[7] ^ 1;
  h[1] = f[1] ^ f[5] ^ f[6] ^ f[7] ^ f[0] ^ 1;
  h[2] = f[2] ^ f[6] ^ f[7] ^ f[0] ^ f[1];
  h[3] = f[3] ^ f[7] ^ f[0] ^ f[1] ^ f[2];
  h[4] = f[4] ^ f[0] ^ f[1] ^ f[2] ^ f[3];
  h[5] = f[5] ^ f[1] ^ f[2] ^ f[3] ^ f[4] ^ 1;
  h[6] = f[6] ^ f[2] ^ f[3] ^ f[4] ^ f[5] ^ 1;
  h[7] = f[7] ^ f[3] ^ f[4] ^ f[5] ^ f[6];
  result = 0;
  for (i = 0;i < 8;++i) result |= h[i] << i;
  return result;
}

int crypto_core_aes128encrypt(
  unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
  unsigned char expanded[4][44];
  unsigned char state[4][4];
  unsigned char newstate[4][4];
  unsigned char roundconstant;
  int i;
  int j;
  int r;

  for (j = 0;j < 4;++j)
    for (i = 0;i < 4;++i)
      expanded[i][j] = k[j * 4 + i];

  roundconstant = 1;
  for (j = 4;j < 44;++j) {
    unsigned char temp[4];
    if (j % 4)
      for (i = 0;i < 4;++i) temp[i] = expanded[i][j - 1];
    else {
      for (i = 0;i < 4;++i) temp[i] = bytesub(expanded[(i + 1) % 4][j - 1]);
      temp[0] ^= roundconstant;
      roundconstant = xtime(roundconstant);
    }
    for (i = 0;i < 4;++i)
      expanded[i][j] = temp[i] ^ expanded[i][j - 4];
  }

  for (j = 0;j < 4;++j)
    for (i = 0;i < 4;++i)
      state[i][j] = in[j * 4 + i] ^ expanded[i][j];

  for (r = 0;r < 10;++r) {
    for (i = 0;i < 4;++i)
      for (j = 0;j < 4;++j)
        newstate[i][j] = bytesub(state[i][j]);
    for (i = 0;i < 4;++i)
      for (j = 0;j < 4;++j)
        state[i][j] = newstate[i][(j + i) % 4];
    if (r < 9)
      for (j = 0;j < 4;++j) {
        unsigned char a0 = state[0][j];
        unsigned char a1 = state[1][j];
        unsigned char a2 = state[2][j];
        unsigned char a3 = state[3][j];
	state[0][j] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
	state[1][j] = xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
	state[2][j] = xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
	state[3][j] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
      }
    for (i = 0;i < 4;++i)
      for (j = 0;j < 4;++j)
        state[i][j] ^= expanded[i][r * 4 + 4 + j];
  }

  for (j = 0;j < 4;++j)
    for (i = 0;i < 4;++i)
      out[j * 4 + i] = state[i][j];

  return 0;
}


#define AES(out,in,k) crypto_core_aes128encrypt(out,in,k,0)

static void store32(unsigned char *x,unsigned long long u)
{
  int i;
  for (i = 3;i >= 0;--i) { x[i] = u; u >>= 8; }
}

static void store64(unsigned char *x,unsigned long long u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = u; u >>= 8; }
}

/*
a = (a + x) * y in the finite field
16 bytes in a
xlen bytes in x; xlen <= 16; x is implicitly 0-padded
16 bytes in y
*/
static void addmul(unsigned char *a,
  const unsigned char *x,unsigned long long xlen,
  const unsigned char *y)
{
  int i;
  int j;
  unsigned char abits[128];
  unsigned char ybits[128];
  unsigned char prodbits[256];
  for (i = 0;i < xlen;++i) a[i] ^= x[i];
  for (i = 0;i < 128;++i) abits[i] = (a[i / 8] >> (7 - (i % 8))) & 1;
  for (i = 0;i < 128;++i) ybits[i] = (y[i / 8] >> (7 - (i % 8))) & 1;
  for (i = 0;i < 256;++i) prodbits[i] = 0;
  for (i = 0;i < 128;++i)
    for (j = 0;j < 128;++j)
      prodbits[i + j] ^= abits[i] & ybits[j];
  for (i = 127;i >= 0;--i) {
    prodbits[i] ^= prodbits[i + 128];
    prodbits[i + 1] ^= prodbits[i + 128];
    prodbits[i + 2] ^= prodbits[i + 128];
    prodbits[i + 7] ^= prodbits[i + 128];
    prodbits[i + 128] ^= prodbits[i + 128];
  }
  for (i = 0;i < 16;++i) a[i] = 0;
  for (i = 0;i < 128;++i) a[i / 8] |= (prodbits[i] << (7 - (i % 8)));
}

static unsigned char zero[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

int crypto_aead_encrypt(
  unsigned char *c,unsigned long long *clen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned char kcopy[16];
  unsigned char H[16];
  unsigned char J[16];
  unsigned char T[16];
  unsigned char accum[16];
  unsigned char stream[16];
  unsigned char finalblock[16];
  unsigned long long i;
  unsigned long long index;

  for (i = 0;i < 16;++i) kcopy[i] = k[i];

  *clen = mlen + 16;
  store64(finalblock,8 * adlen);
  store64(finalblock + 8,8 * mlen);

  AES(H,zero,kcopy);

  for (i = 0;i < 12;++i) J[i] = npub[i];
  index = 1;
  store32(J + 12,index);
  AES(T,J,kcopy);

  for (i = 0;i < 16;++i) accum[i] = 0;

  while (adlen > 0) {
    unsigned long long blocklen = 16;
    if (adlen < blocklen) blocklen = adlen;
    addmul(accum,ad,blocklen,H);
    ad += blocklen;
    adlen -= blocklen;
  }

  while (mlen > 0) {
    unsigned long long blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    ++index;
    store32(J + 12,index);
    AES(stream,J,kcopy);
    for (i = 0;i < blocklen;++i) c[i] = m[i] ^ stream[i];
    addmul(accum,c,blocklen,H);
    c += blocklen;
    m += blocklen;
    mlen -= blocklen;
  }

  addmul(accum,finalblock,16,H);
  for (i = 0;i < 16;++i) c[i] = T[i] ^ accum[i];
  return 0;
}

int crypto_aead_decrypt(
  unsigned char *m,unsigned long long *outputmlen,
  unsigned char *nsec,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *ad,unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned char kcopy[16];
  unsigned char H[16];
  unsigned char J[16];
  unsigned char T[16];
  unsigned char accum[16];
  unsigned char stream[16];
  unsigned char finalblock[16];
  unsigned long long mlen;
  unsigned long long origmlen;
  unsigned long long index;
  unsigned long long i;
  const unsigned char *origc;

  for (i = 0;i < 16;++i) kcopy[i] = k[i];

  if (clen < 16) return -1;
  mlen = clen - 16;

  store64(finalblock,8 * adlen);
  store64(finalblock + 8,8 * mlen);

  AES(H,zero,kcopy);

  for (i = 0;i < 12;++i) J[i] = npub[i];
  index = 1;
  store32(J + 12,index);
  AES(T,J,kcopy);

  for (i = 0;i < 16;++i) accum[i] = 0;

  while (adlen > 0) {
    unsigned long long blocklen = 16;
    if (adlen < blocklen) blocklen = adlen;
    addmul(accum,ad,blocklen,H);
    ad += blocklen;
    adlen -= blocklen;
  }

  origc = c;
  origmlen = mlen;
  while (mlen > 0) {
    unsigned long long blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    addmul(accum,c,blocklen,H);
    c += blocklen;
    mlen -= blocklen;
  }

  addmul(accum,finalblock,16,H);
  for (i = 0;i < 16;++i) accum[i] ^= T[i];
  if (crypto_verify_16(accum,c) != 0) return -1;

  c = origc;
  mlen = origmlen;
  *outputmlen = mlen;

  while (mlen > 0) {
    unsigned long long blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    ++index;
    store32(J + 12,index);
    AES(stream,J,kcopy);
    for (i = 0;i < blocklen;++i) m[i] = c[i] ^ stream[i];
    c += blocklen;
    m += blocklen;
    mlen -= blocklen;
  }

  return 0;
}
