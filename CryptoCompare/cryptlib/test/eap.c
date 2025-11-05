/****************************************************************************
*																			*
*								cryptlib EAP Code							*
*						Copyright Peter Gutmann 2016-2021					*
*																			*
****************************************************************************/

/* Under Windows debug mode everything is enabled by default when building 
   cryptlib, so we also enable the required options here.  Under Unix it'll
   need to be enabled manually by adding '-DUSE_EAP -DUSE_DES' to the build 
   command.  Note that this needs to be done via the build process even if
   it's already defined in config.h since that only applies to cryptlib, not
   to this module */

#if defined( _MSC_VER ) && !defined( NDEBUG )
  #define USE_EAP
  #define USE_DES
#endif /* Windows debug build */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !( defined( _WIN32 ) || defined( _WIN64 ) )
  #include <locale.h>
#endif /* !Windows */
#include "cryptlib.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

/* Check that EAP and any required ancilliary capabilities are enabled in 
   the build */

#if defined( USE_EAP ) && !defined( USE_DES )
  #error USE_EAP requires USE_DES for MSCHAPv2
#endif /* !USE_EAP */

/* RADIUS attribute types and flags */

#define RADIUS_SUBTYPE_USERNAME			1
#define RADIUS_SUBTYPE_PASSWORD			2
#define RADIUS_SUBTYPE_CHAP				3
#define RADIUS_SUBTYPE_CHAPCHALLENGE	60

#define VENDOR_ID_MICROSOFT				311

#define MSCHAP_CHALLENGE				11
#define MSCHAP2_RESPONSE				25

#define FLAG_MANDATORY					0x40
#define FLAG_VENDORIDPRESENT			0x80

/* EAP subprotocol and authentication types */

typedef enum { PROTOCOL_EAPTTLS, PROTOCOL_PEAP, PROTOCOL_PEAP_NPS, 
			   PROTOCOL_LAST } PROTOCOL_TYPE; 
typedef enum { AUTH_PAP, AUTH_CHAP, AUTH_MSCHAPV2, AUTH_LAST } AUTH_TYPE;

/* The maximum size of the buffer to hold the authentication data sent over
   the EAP subprotocol tunnel */

#define EAP_BUFFER_SIZE		256

/* Useful defines normally in crypt.h/test.h */

#define BOOLEAN				int
#define BYTE				unsigned char
#ifndef TRUE
  #define FALSE				0
  #define TRUE				!FALSE
#endif /* TRUE */

/* Additional debugging suppport when we're built in debug mode */

#ifdef NDEBUG
  #define DEBUG_PUTS( x )
  #define DEBUG_PRINT( x )
  #define DEBUG_DUMPHEX( x, xLen )
#else
  #include <stdio.h>
  static void dumpHexData( const BYTE *data, const int dataLen );
  #define DEBUG_PUTS( x )			printf( "%s\n", x )
  #define DEBUG_PRINT( x )			printf x
  #define DEBUG_DUMPHEX				dumpHexData
#endif /* NDEBUG */

#ifdef USE_EAP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Convert a password to Windows-format Unicode.  Note that this conversion 
   may run into i18n problems if mapping from the source system's local 
   format to Windows-format Unicode isn't possible.  For this reason use of 
   non-basic-ASCII+latin1 characters is discouraged unless you're sure that 
   the local system, conversion process, and remote system all agree on what 
   translates to what */

static int convertToUnicode( BYTE *unicodePassword, 
							 const int unicodePasswordMaxLength,
							 const BYTE *password, const int passwordLength )
	{
	wchar_t wcsBuffer[ 256 + 1 ];
#if defined( _WIN32 ) || defined( _WIN64 )
	const int unicodePasswordLength = \
				MultiByteToWideChar( CP_UTF8, 0, password, passwordLength,
									 NULL, 0 );
#else
	const int unicodePasswordLength = ( int ) \
				mbstowcs( NULL, password, passwordLength );
#endif /* Windows vs. Unix */
	int i, status;

	/* Make sure that the converted result will fit */
	if( unicodePasswordLength <= 0 )
		return( CRYPT_ERROR_BADDATA );
	if( unicodePasswordLength * 2 > unicodePasswordMaxLength || \
		unicodePasswordLength * 2 > 256 )
		return( CRYPT_ERROR_OVERFLOW );

	/* Convert the input string into 16-bit little-endian Windows-style
	   Unicode.  We have to be careful here because wchar_t can be 16 or 32 
	   bits and of either endianness while Windows Unicode is 16-bit little-
	   endian.  In addition the Windows mbstowcs() can't do UTF-8 so we 
	   have to use MultiByteToWideChar() instead, however since we're 
	   hardcoding in UTF-8 to be compatible with the Unix usage it also
	   won't convert from a standard Windows locale which will never be
	   UTF-8 */
	memset( unicodePassword, 0, unicodePasswordMaxLength );
#if defined( _WIN32 ) || defined( _WIN64 )
	status = MultiByteToWideChar( CP_UTF8, 0, password, passwordLength,
								  wcsBuffer, 256 );
#else
	status = mbstowcs( wcsBuffer, password, passwordLength );
#endif /* Windows vs. Unix */
	if( status <= 0 )
		return( CRYPT_ERROR_BADDATA );
	for( i = 0; i < unicodePasswordLength; i++ )
		{
		const wchar_t wCh = wcsBuffer[ i ];

		/* The string is now in the local system's wchar_t form, convert 
		   it to Windows Unicode form */
		if( wCh > 0x7FFF )
			return( CRYPT_ERROR_BADDATA );
		unicodePassword[ i * 2 ] = wCh & 0xFF;
		unicodePassword[ ( i * 2 ) + 1 ] = ( wCh >> 8 ) & 0xFF;
		}

	return( unicodePasswordLength * 2 );
	}

/****************************************************************************
*																			*
*					Obsolete Crypto Algorithms for MS-CHAP					*
*																			*
****************************************************************************/

/* Public-domain MD4 implementation, see comment below */

#define MD4_BLOCK_LENGTH			64
#define MD4_DIGEST_LENGTH			16

typedef struct {
	unsigned long state[ 4 ];		/* State */
	long count;						/* Number of bits */
	BYTE buffer[ MD4_BLOCK_LENGTH ];/* input buffer */
	} MD4_CTX;

/* ===== start - public domain MD4 implementation ===== */
/*      $OpenBSD: md4.c,v 1.7 2005/08/08 08:05:35 espie Exp $   */

/*
 * This code implements the MD4 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 * Todd C. Miller modified the MD5 code to do MD4 based on RFC 1186.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD4Context structure, pass it to MD4Init, call MD4Update as
 * needed on buffers full of bytes, and then call MD4Final, which
 * will fill a supplied 16-byte array with the digest.
 */

#define MD4_DIGEST_STRING_LENGTH        (MD4_DIGEST_LENGTH * 2 + 1)

static void
MD4Transform(unsigned long state[4], const BYTE block[MD4_BLOCK_LENGTH]);

#define PUT_64BIT_LE(cp, value) do {                \
        (cp)[7] = 0;                                \
        (cp)[6] = 0;                                \
        (cp)[5] = 0;                                \
        (cp)[4] = 0;                                \
        (cp)[3] = (BYTE)((value) >> 24);            \
        (cp)[2] = (BYTE)((value) >> 16);            \
        (cp)[1] = (BYTE)((value) >> 8);             \
        (cp)[0] = (BYTE)(value); } while (0)

#define PUT_32BIT_LE(cp, value) do {                \
        (cp)[3] = (BYTE)((value) >> 24);            \
        (cp)[2] = (BYTE)((value) >> 16);            \
        (cp)[1] = (BYTE)((value) >> 8);             \
        (cp)[0] = (BYTE)(value); } while (0)

static BYTE PADDING[MD4_BLOCK_LENGTH] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Start MD4 accumulation.
 * Set bit count to 0 and buffer to mysterious initialization constants.
 */
static void MD4Init(MD4_CTX *ctx)
{
        ctx->count = 0;
        ctx->state[0] = 0x67452301;
        ctx->state[1] = 0xefcdab89;
        ctx->state[2] = 0x98badcfe;
        ctx->state[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static void MD4Update(MD4_CTX *ctx, const unsigned char *input, size_t len)
{
        size_t have, need;

        /* Check how many bytes we already have and how many more we need. */
        have = (size_t)((ctx->count >> 3) & (MD4_BLOCK_LENGTH - 1));
        need = MD4_BLOCK_LENGTH - have;

        /* Update bitcount */
        ctx->count += (unsigned long)len << 3;

        if (len >= need) {
                if (have != 0) {
                        memcpy(ctx->buffer + have, input, need);
                        MD4Transform(ctx->state, ctx->buffer);
                        input += need;
                        len -= need;
                        have = 0;
                }

                /* Process data in MD4_BLOCK_LENGTH-byte chunks. */
                while (len >= MD4_BLOCK_LENGTH) {
                        MD4Transform(ctx->state, input);
                        input += MD4_BLOCK_LENGTH;
                        len -= MD4_BLOCK_LENGTH;
                }
        }

        /* Handle any remaining bytes of data. */
        if (len != 0)
                memcpy(ctx->buffer + have, input, len);
}

/*
 * Pad pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static void MD4Pad(MD4_CTX *ctx)
{
        BYTE count[8];
        size_t padlen;

        /* Convert count to 8 bytes in little endian order. */
        PUT_64BIT_LE(count, ctx->count);

        /* Pad out to 56 mod 64. */
        padlen = MD4_BLOCK_LENGTH -
            ((ctx->count >> 3) & (MD4_BLOCK_LENGTH - 1));
        if (padlen < 1 + 8)
                padlen += MD4_BLOCK_LENGTH;
        MD4Update(ctx, PADDING, padlen - 8);            /* padlen - 8 <= 64 */
        MD4Update(ctx, count, 8);
}

/*
 * Final wrapup--call MD4Pad, fill in digest and zero out ctx.
 */
static void MD4Final(unsigned char digest[MD4_DIGEST_LENGTH], MD4_CTX *ctx)
{
        int i;

        MD4Pad(ctx);
        if (digest != NULL) {
                for (i = 0; i < 4; i++)
                        PUT_32BIT_LE(digest + i * 4, ctx->state[i]);
                memset(ctx, 0, sizeof(*ctx));
        }
}

/* The three core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) ((x & y) | (x & z) | (y & z))
#define F3(x, y, z) (x ^ y ^ z)

/* This is the central step in the MD4 algorithm. */
#define MD4STEP(f, w, x, y, z, data, s) \
        ( w += f(x, y, z) + data,  w = ((w<<s)&0xFFFFFFFF) | (w&0xFFFFFFFF)>>(32-s) )
		/* Added 32-bit masking to avoid having to use system-specific 
		  fixed-size 32-bit data types - pcg */

/*
 * The core of the MD4 algorithm, this alters an existing MD4 hash to
 * reflect the addition of 16 longwords of new data.  MD4Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void
MD4Transform(unsigned long state[4], const BYTE block[MD4_BLOCK_LENGTH])
{
        unsigned long a, b, c, d, in[MD4_BLOCK_LENGTH / 4];

        for (a = 0; a < MD4_BLOCK_LENGTH / 4; a++) {
                in[a] = (unsigned long)(
                    (unsigned long)(block[a * 4 + 0]) |
                    (unsigned long)(block[a * 4 + 1]) <<  8 |
                    (unsigned long)(block[a * 4 + 2]) << 16 |
                    (unsigned long)(block[a * 4 + 3]) << 24);
        }

        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];

        MD4STEP(F1, a, b, c, d, in[ 0],  3);
        MD4STEP(F1, d, a, b, c, in[ 1],  7);
        MD4STEP(F1, c, d, a, b, in[ 2], 11);
        MD4STEP(F1, b, c, d, a, in[ 3], 19);
        MD4STEP(F1, a, b, c, d, in[ 4],  3);
        MD4STEP(F1, d, a, b, c, in[ 5],  7);
        MD4STEP(F1, c, d, a, b, in[ 6], 11);
        MD4STEP(F1, b, c, d, a, in[ 7], 19);
        MD4STEP(F1, a, b, c, d, in[ 8],  3);
        MD4STEP(F1, d, a, b, c, in[ 9],  7);
        MD4STEP(F1, c, d, a, b, in[10], 11);
        MD4STEP(F1, b, c, d, a, in[11], 19);
        MD4STEP(F1, a, b, c, d, in[12],  3);
        MD4STEP(F1, d, a, b, c, in[13],  7);
        MD4STEP(F1, c, d, a, b, in[14], 11);
        MD4STEP(F1, b, c, d, a, in[15], 19);

        MD4STEP(F2, a, b, c, d, in[ 0] + 0x5a827999,  3);
        MD4STEP(F2, d, a, b, c, in[ 4] + 0x5a827999,  5);
        MD4STEP(F2, c, d, a, b, in[ 8] + 0x5a827999,  9);
        MD4STEP(F2, b, c, d, a, in[12] + 0x5a827999, 13);
        MD4STEP(F2, a, b, c, d, in[ 1] + 0x5a827999,  3);
        MD4STEP(F2, d, a, b, c, in[ 5] + 0x5a827999,  5);
        MD4STEP(F2, c, d, a, b, in[ 9] + 0x5a827999,  9);
        MD4STEP(F2, b, c, d, a, in[13] + 0x5a827999, 13);
        MD4STEP(F2, a, b, c, d, in[ 2] + 0x5a827999,  3);
        MD4STEP(F2, d, a, b, c, in[ 6] + 0x5a827999,  5);
        MD4STEP(F2, c, d, a, b, in[10] + 0x5a827999,  9);
        MD4STEP(F2, b, c, d, a, in[14] + 0x5a827999, 13);
        MD4STEP(F2, a, b, c, d, in[ 3] + 0x5a827999,  3);
        MD4STEP(F2, d, a, b, c, in[ 7] + 0x5a827999,  5);
        MD4STEP(F2, c, d, a, b, in[11] + 0x5a827999,  9);
        MD4STEP(F2, b, c, d, a, in[15] + 0x5a827999, 13);

        MD4STEP(F3, a, b, c, d, in[ 0] + 0x6ed9eba1,  3);
        MD4STEP(F3, d, a, b, c, in[ 8] + 0x6ed9eba1,  9);
        MD4STEP(F3, c, d, a, b, in[ 4] + 0x6ed9eba1, 11);
        MD4STEP(F3, b, c, d, a, in[12] + 0x6ed9eba1, 15);
        MD4STEP(F3, a, b, c, d, in[ 2] + 0x6ed9eba1,  3);
        MD4STEP(F3, d, a, b, c, in[10] + 0x6ed9eba1,  9);
        MD4STEP(F3, c, d, a, b, in[ 6] + 0x6ed9eba1, 11);
        MD4STEP(F3, b, c, d, a, in[14] + 0x6ed9eba1, 15);
        MD4STEP(F3, a, b, c, d, in[ 1] + 0x6ed9eba1,  3);
        MD4STEP(F3, d, a, b, c, in[ 9] + 0x6ed9eba1,  9);
        MD4STEP(F3, c, d, a, b, in[ 5] + 0x6ed9eba1, 11);
        MD4STEP(F3, b, c, d, a, in[13] + 0x6ed9eba1, 15);
        MD4STEP(F3, a, b, c, d, in[ 3] + 0x6ed9eba1,  3);
        MD4STEP(F3, d, a, b, c, in[11] + 0x6ed9eba1,  9);
        MD4STEP(F3, c, d, a, b, in[ 7] + 0x6ed9eba1, 11);
        MD4STEP(F3, b, c, d, a, in[15] + 0x6ed9eba1, 15);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
}
/* ===== end - public domain MD4 implementation ===== */

static void md4Hash( const void *data, const int dataLength, BYTE *hashValue )
	{
	MD4_CTX md4CTX;

	MD4Init( &md4CTX );
	MD4Update( &md4CTX, data, dataLength );
	MD4Final( hashValue, &md4CTX );
	}

/****************************************************************************
*																			*
*									MS-CHAPv2								*
*																			*
****************************************************************************/

/* MSCHAPv2 functionality as specified in RFC 2759.  This is a great
   teaching example of every mistake you can make in challenge-response 
   authentication, it gets pretty much everything wrong from start to 
   finish, but we have to implement it because so much stuff uses it */

/* ChallengeHash(), RFC 2759 page 8 */

static int ChallengeHash( const BYTE PeerChallenge[ 16 ], 
						  const BYTE AuthenticatorChallenge[ 16 ],
						  const BYTE *UserName, const int UserNameLength,
						  BYTE Challenge[ 8 ] )
	{
	CRYPT_CONTEXT hashContext;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ];
	int hashSize, status;

	status = cryptCreateContext( &hashContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_SHA1 );
	if( cryptStatusError( status ) )
		return( status );
	cryptEncrypt( hashContext, ( void * ) PeerChallenge, 16 );
	cryptEncrypt( hashContext, ( void * ) AuthenticatorChallenge, 16 );
	cryptEncrypt( hashContext, ( void * ) UserName, UserNameLength );
	status = cryptEncrypt( hashContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( hashContext, 
										  CRYPT_CTXINFO_HASHVALUE,
										  hashValue, &hashSize );
		}
	cryptDestroyContext( hashContext );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( Challenge, hashValue, 8 );
	memset( hashValue, 0, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* NtPasswordHash(), RFC 2759 page 9 */

static int NtPasswordHash( const BYTE *Password, const int PasswordLength,
						   BYTE PasswordHash[ 16 ] )
	{
	md4Hash( Password, PasswordLength, PasswordHash );

	return( CRYPT_OK );
	}

/* ChallengeResponse(), RFC 2759 page 9.
   DesEncrypt(), RFC 2759 page 10 */

static int DesEncrypt( const BYTE Clear[ 8 ], 
					   const BYTE Key[ 7 ], 
					   BYTE Cypher[ 8 ] )
	{
	CRYPT_CONTEXT cryptContext;
	BYTE desKey[ 8 ];
	int i, status;

	/* Convert the 56-bit Key value into the eight 7-bit key data bytes 
	   required by DES.  This involves first expanding the 56 input bits
	   into 64 7-bit bytes and then shifting each byte up by one since the
	   parity bits are in the LSB, not the MSB */
	desKey[ 0 ] = Key[ 0 ] >> 0x01;
	desKey[ 1 ] = ( ( Key[ 0 ] & 0x01 ) << 6 ) | ( Key[ 1 ] >> 2 );
	desKey[ 2 ] = ( ( Key[ 1 ] & 0x03 ) << 5 ) | ( Key[ 2 ] >> 3 );
 	desKey[ 3 ] = ( ( Key[ 2 ] & 0x07 ) << 4 ) | ( Key[ 3 ] >> 4 );
	desKey[ 4 ] = ( ( Key[ 3 ] & 0x0F ) << 3 ) | ( Key[ 4 ] >> 5 );
	desKey[ 5 ] = ( ( Key[ 4 ] & 0x1F ) << 2 ) | ( Key[ 5 ] >> 6 );
	desKey[ 6 ] = ( ( Key[ 5 ] & 0x3F ) << 1 ) | ( Key[ 6 ] >> 7 );
	desKey[ 7 ] = Key[ 6 ] & 0x7F;
	for( i = 0; i < 8; i++ )
		desKey[ i ] = ( desKey[ i ] << 1 ) & 0xFE;

	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_DES );
	if( cryptStatusError( status ) )
		return( status );
	cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE, CRYPT_MODE_ECB );
	status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY, 
									  desKey, 8 );
	if( cryptStatusOK( status ) )
		{
		memcpy( Cypher, Clear, 8 );
		status = cryptEncrypt( cryptContext, Cypher, 8 );
		}
	cryptDestroyContext( cryptContext );
	memset( desKey, 0, 8 );

	return( status );
	}

static int ChallengeResponse( const BYTE Challenge[ 8 ], 
							  const BYTE PasswordHash[ 16 ],
							  BYTE Response[ 24 ] )
	{
	BYTE ZPasswordHash[ 21 ];
	int status;

	memset( ZPasswordHash, 0, 21 );
	memcpy( ZPasswordHash, PasswordHash, 16 );

	status = DesEncrypt( Challenge, ZPasswordHash, Response );
	if( cryptStatusOK( status ) )
		status = DesEncrypt( Challenge, ZPasswordHash + 7, Response + 8 );
	if( cryptStatusOK( status ) )
		status = DesEncrypt( Challenge, ZPasswordHash + 14, Response + 16 );
	memset( ZPasswordHash, 0, 21 );

	return( status );
	}

/* GenerateNTResponse, RFC 2759 p.7 */

static int GenerateNTResponse( const BYTE AuthenticatorChallenge[ 16 ],
							   const BYTE PeerChallenge[ 16 ],
							   const BYTE *UserName, const int UserNameLength,
							   const BYTE *Password, const int PasswordLength,
							   BYTE Response[ 24 ] )
	{
	BYTE Challenge[ 8 ], PasswordHash[ 16 ];
	int status;

	status = ChallengeHash( PeerChallenge, AuthenticatorChallenge,
							UserName, UserNameLength, Challenge );
	if( cryptStatusOK( status ) )
		status = NtPasswordHash( Password, PasswordLength, PasswordHash );
	if( cryptStatusOK( status ) )
		status = ChallengeResponse( Challenge, PasswordHash, Response );
	memset( Challenge, 0, 8 );
	memset( PasswordHash, 0, 16 );

	return( status );
	}

/****************************************************************************
*																			*
*							EAP-TTLS Interface Routines						*
*																			*
****************************************************************************/

/* Encode an attribute in TTLS AVP format:

	0..3:	uint32	type
	4:		byte	flags
	5..7:	uint24	length		// Including header size
  [	8..11:	uint32	vendorID ]

   The TTLS AVP format, although it's built on RADIUS values, uses the 
   DIAMETER encoding which requires that all TLVs be zero-padded to 4-byte 
   alignment for no known reason.  The following function adds the necessary 
   zero padding alongside performing the TLV encoding.  encodeAVP() assumes
   that getAVPsize() has been called previously in order to verify available
   space */

#define getPadSize( length )	( ( 4 - ( ( length ) % 4 ) ) % 4 )
#define getHeaderLen( vendorID ) \
								( 8 + ( ( vendorID > 0 ) ? 4 : 0 ) )

static int getVendorAVPsize( const int vendorID, const int valueLen )
	{
	const int length = getHeaderLen( vendorID ) + valueLen;

	return( length + getPadSize( length ) );
	}

#define getAVPsize( valueLen ) \
		getVendorAVPsize( CRYPT_UNUSED, valueLen )

static int encodeVendorAVP( BYTE *dataPtr, const int type, 
							const int vendorID, const BYTE *value, 
							const int valueLen )
	{
	const int headerLen = getHeaderLen( vendorID );
	const int totalLen = headerLen + valueLen;
	const int padSize = getPadSize( totalLen );

	/* Encode the header */
	memset( dataPtr, 0, 16 );
	dataPtr[ 2 ] = ( type >> 8 ) & 0xFF;
	dataPtr[ 3 ] = type & 0xFF;
	dataPtr[ 4 ] = FLAG_MANDATORY;
	dataPtr[ 6 ] = ( totalLen >> 8 ) & 0xFF;
	dataPtr[ 7 ] = totalLen & 0xFF;
	if( vendorID > 0 )
		{
		dataPtr[ 4 ] |= FLAG_VENDORIDPRESENT;
		dataPtr[ 10 ] = ( vendorID >> 8 ) & 0xFF;
		dataPtr[ 11 ] = vendorID & 0xFF;
		}

	/* Encode the payload and padding */
	memcpy( dataPtr + headerLen, value, valueLen );
	if( padSize > 0 )
		memset( dataPtr + totalLen, 0, padSize );

	return( totalLen + padSize );
	}

#define encodeAVP( dataPtr, type, value, valueLen ) \
		encodeVendorAVP( dataPtr, type, CRYPT_UNUSED, value, valueLen )

/* Create a TTLS AVP encoding of the PAP data:

	{ User-Name, byte[] data },
	{ Password, byte[] data } */

static int createTTLSAVPPAP( BYTE *ttlsAVP, const int ttlsAVPmaxLength, 
							 int *ttlsAVPlength,
							 const void *userName, const int userNameLength,
							 const void *password, const int passwordLength )
	{
	int ttlsAVPlen;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 || \
		passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( getAVPsize( userNameLength ) + \
		getAVPsize( passwordLength ) > ttlsAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Set up the RADIUS User-Name and Password attributes */
	ttlsAVPlen = encodeAVP( ttlsAVP, RADIUS_SUBTYPE_USERNAME, 
							userName, userNameLength );
	ttlsAVPlen += encodeAVP( ttlsAVP + ttlsAVPlen, RADIUS_SUBTYPE_PASSWORD, 
							 password, passwordLength );
	*ttlsAVPlength = ttlsAVPlen;

	return( CRYPT_OK );
	}

/* Create a TTLS AVP encoding of the CHAP data:

	{ User-Name, byte[] data },
	{ CHAP-Challenge, byte[16] data },
	{ CHAP-Password, byte ident || 
					 byte[16] data } */

static int createTTLSAVPCHAP( BYTE *ttlsAVP, const int ttlsAVPmaxLength, 
							  int *ttlsAVPlength,
							  const void *userName, const int userNameLength,
							  const void *password, const int passwordLength,
							  const void *chapChallenge )
	{
	CRYPT_CONTEXT cryptContext;
	const BYTE identifier = ( ( BYTE * ) chapChallenge )[ 16 ];
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ], chapResponse[ CRYPT_MAX_HASHSIZE ];
	int hashValueLength, ttlsAVPlen, status;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 || \
		passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( getAVPsize( userNameLength ) + getAVPsize( 16 ) + \
		getAVPsize( 17 ) > ttlsAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Create the CHAP response: MD5( identifier || password || challenge ) */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_MD5 );
	if( cryptStatusError( status ) )
		return( status );
	cryptEncrypt( cryptContext, ( void * ) &identifier, 1 );
	cryptEncrypt( cryptContext, ( void * ) password, passwordLength );
	cryptEncrypt( cryptContext, ( void * ) chapChallenge, 16 );
	status = cryptEncrypt( cryptContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptContext, 
										  CRYPT_CTXINFO_HASHVALUE, 
										  hashValue, &hashValueLength );
		}
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Encode the CHAP response: identifier || hashValue */
	chapResponse[ 0 ] = identifier;
	memcpy( chapResponse + 1, hashValue, 16 );

	/* Set up the RADIUS User-Name attribute */
	ttlsAVPlen = encodeAVP( ttlsAVP, RADIUS_SUBTYPE_USERNAME, 
							userName, userNameLength );

	/* Set up the RADIUS CHAP-Challenge and CHAP-Password attributes */
	ttlsAVPlen += encodeAVP( ttlsAVP + ttlsAVPlen, RADIUS_SUBTYPE_CHAPCHALLENGE, 
							 chapChallenge, 16 );
	ttlsAVPlen += encodeAVP( ttlsAVP + ttlsAVPlen, RADIUS_SUBTYPE_CHAP, 
							 chapResponse, 17 );
	*ttlsAVPlength = ttlsAVPlen;

	return( CRYPT_OK );
	}

/* Create a TTLS AVP encoding of the MSCHAPv2 data:

	{ User-Name, byte[] data },
	{ MS-CHAP-Challenge, byte[16] chapChallenge },
	{ MS-CHAP2-Response, byte vendorIdent || 
						 byte vendorFlags = 0 || 
						 byte[16] vendorPeerChallenge	// MS-CHAP challenge data
						 byte[8] vendorReserved = { 0 } ||
						 byte[24] vendorResponse }		// MS-CHAP response data 
	*/

static int createTTLSAVPMSCHAPv2( BYTE *ttlsAVP, const int ttlsAVPmaxLength, 
								  int *ttlsAVPlength,
								  const void *userName, const int userNameLength,
								  const void *password, const int passwordLength,
								  const void *chapChallenge )
	{
	const BYTE *chapChallengePtr = chapChallenge;
	const BYTE identifier = ( ( BYTE * ) chapChallenge )[ 16 ];
	BYTE unicodePassword[ 256 ], chapResponse[ 128 ];
	int unicodePasswordLength, ttlsAVPlen, status;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 || \
		passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( getAVPsize( userNameLength ) + \
		getVendorAVPsize( VENDOR_ID_MICROSOFT, 16 ) + \
		getVendorAVPsize( VENDOR_ID_MICROSOFT, 50 ) > ttlsAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Convert the password to Windows-format Unicode */
	status = unicodePasswordLength = \
				convertToUnicode( unicodePassword, 256, 
								  password, passwordLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the MSCHAPv2 challenge response */
	memset( chapResponse, 0, 128 );
	chapResponse[ 0 ] = identifier;							/* MS-CHAP ident */
	memcpy( chapResponse + 2, chapChallengePtr + 16, 16 );	/* MS-CHAP challenge */
	status = GenerateNTResponse( chapChallengePtr, chapChallengePtr + 16,
								 userName, userNameLength,
								 unicodePassword, unicodePasswordLength, 
								 chapResponse + 26 );		/* MS-CHAP response */
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the RADIUS User-Name attribute */
	ttlsAVPlen = encodeAVP( ttlsAVP, RADIUS_SUBTYPE_USERNAME, 
							userName, userNameLength );

	/* Set up the RADIUS MS-CHAP-Challenge and MS-CHAP2-Response attributes */
	ttlsAVPlen += encodeVendorAVP( ttlsAVP + ttlsAVPlen, MSCHAP_CHALLENGE, 
								   VENDOR_ID_MICROSOFT, chapChallengePtr, 16 );
	ttlsAVPlen += encodeVendorAVP( ttlsAVP + ttlsAVPlen, MSCHAP2_RESPONSE, 
								   VENDOR_ID_MICROSOFT, chapResponse, 50 );
	*ttlsAVPlength = ttlsAVPlen;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								PEAP Interface Routines						*
*																			*
****************************************************************************/

/* Create a PEAP AVP encoding of the MSCHAPv2 data:

  [ EAP type, ID, and length fields omitted, because Microsoft ]
	byte	type = 26 / 0x1A		// MS-CHAP2-Response = EAP subtype field
	byte	opcode = 2				// Response = PEAP message
	byte	MSCHAPv2ID				// Copied from request
	uint16	length = 54+n / 0x36+n	// 6 + payload + username length, see note
	byte	value-size = 49 / 0x31	// Fixed at 49 bytes
		byte[16] challenge			// Our challenge to server
		byte[8]	reserved = { 0 }
		byte[24] response			// NT-Response
		byte	flags = 0
	byte[n]	name					// Remaining bytes = User name 

   Since this uses a completely different encoding than EAP-TTLS and we only
   need to do MSCHAPv2 (in fact it's pretty much the only thing defined for
   PEAP), we hardcode in the message fields as a fixed data block and copy 
   the ephemeral fields into the appropriate locations.  The Challenge field
   at offset 6 is our challenge to the server which isn't used for anything 
   so we just hardcode in a placeholder string of '#'.

   Note that the length field buried inside the packet at offset 4 has a 
   value of 54+n rather than the expected 55+n that the packet is long, this
   is because the packet is preceded by an EAP header that isn't there and
   the first byte is counted as being part of the nonexistent EAP header
   rather than the packet itself, so the length field records a value one 
   byte shorter than the actual length.

   Although the user name field at the end is optional, in practice it must 
   be sent or FreeRADIUS will fail the authentication */

static int createPEAPAVPMSCHAPv2( BYTE *peapAVP, const int peapAVPmaxLength, 
								  int *peapAVPlength,
								  const void *userName, const int userNameLength,
								  const void *password, const int passwordLength,
								  const void *chapChallenge, const int chapID )
	{
	static const BYTE peapMSCHAPResponse[] = \
				"\x1A\x02\xFF\x00\x36\x31"
		/*  6 */	"################"						/* Challenge */
		/* 22 */	"\x00\x00\x00\x00\x00\x00\x00\x00"		/* Reserved */
		/* 30 */	"************************"				/* Response */
		/* 54 */	"\x00";									/* Flags */
		/* 55 */											/* Username */
	const int peapMSCHAPResponseLength = sizeof( peapMSCHAPResponse ) - 1;
	BYTE unicodePassword[ 256 ];
	int unicodePasswordLength;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 || \
		passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( peapMSCHAPResponseLength + userNameLength > peapAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	*peapAVPlength = peapMSCHAPResponseLength;

	/* Convert the password to Windows-format Unicode */
	unicodePasswordLength = convertToUnicode( unicodePassword, 256, 
											  password, passwordLength );
	if( unicodePasswordLength < 0 )
		return( unicodePasswordLength );

	/* Set up the PEAP MS-CHAP-Response, including the mandatory optional
	   user name */
	memcpy( peapAVP, peapMSCHAPResponse, peapMSCHAPResponseLength );
	peapAVP[ 2 ] = chapID;						/* MS-CHAP ident */
#if 0		/* Optionally make our challenge non-fixed */
	{
	const BYTE *challengePtr = chapChallenge;
	int i;

	/* Turn our fixed challenge into a random-ish looking one in case the 
	   other side checks for static values */
	for( i = 0; i < 16; i++ )
		peapAVP[ 6 + i ] = challengePtr[ i ] ^ ( 0x55 - i );
	}
#endif /* 0 */
#if 1		/* See comment above */
	memcpy( peapAVP + 55, userName, userNameLength );
	peapAVP[ 4 ] += userNameLength;
	*peapAVPlength += userNameLength;
#endif /* 0 */

	/* Generate the MSCHAPv2 response */
	return( GenerateNTResponse( chapChallenge, peapAVP + 6,
								userName, userNameLength,
								unicodePassword, unicodePasswordLength, 
								peapAVP + 30 ) );
	}

/* Microsoft servers can send one or more Extension Requests, in EAP rather 
   than PEAP format, using Microsoft-proprietary attributes and contents.  
   The most common one that's sent is Capabilities Negotiation Method, 
   documented in "[MS-PEAP]: Protected Extensible Authentication Protocol 
   (PEAP)", section 2.2.8.3:

	byte	code = 1				// Request
	byte	packet ID
	uint16	length = 16				// Including header
	byte	type = 254				// Expanded Types
	uint24	vendorID = 311			// Microsodt
	uint32	vendorType = 34			// Capabilities Negotiation Method
	byte[]	vendorData = 00 00 00 01
									// 32-bit flag, bit 31 = supports PEAP 
									// phase 2 fragmentation

   No idea what you're supposed to do with this if you're a non-Microsoft 
   product, but in most cases wpa_supplicant just sends another copy of the 
   Identity Response which produces the desired effect (but see also further
   down on wpa_supplicant's handling of vendorType = 33 requests).  
   
   However since we know what it is we can send it back, but with the 
   fragmentation flag cleared since it's unclear what we need to do to 
   handle this.  According to the above doc if a packet is larger than 
   MaxSendPacketSize then it's fragmented but there's no indication what 
   MaxSendPacketSize is apart from that it's obtained via another Microsoft-
   proprietary EAP message, nor is there any indication of what "PEAP 
   fragmentation" is beyond the already-present UDP, RADIUS, and EAP 
   fragmentation (the "phase 2" refers to the traffic inside the TLS tunnel 
   so it may be some sort of additional fragmentation at the PEAP level to 
   go with the other three?).
   
   Another possible message is SoH EAP Extensions Method, documented in 
   "[MS-PEAP]: Protected Extensible Authentication Protocol (PEAP)", section 
   2.2.8.2:

	byte	code = 1				// Request
	byte	packet ID
	uint16	length					// Including header
	byte	type = 254				// Expanded Types
	uint24	vendorID = 311			// Microsodt
	uint32	vendorType = 33			// Capabilities Negotiation Method
	byte[]	vendorData = 00 02 00 00
									// Magic value for SoH Request

   We're supposed to respond to this with an SoH TLV, whose payload is
   defined in the TCG's "TNC IF-TNCCS: Protocol Bindings for SoH" section
   3.5, "Statement of Health (SoH) Message", which contains a section
   3.5.1.3 System SoH (SSoH), but this is a composite field containing huge
   masses of information, way too complex to fill in, so we just resend the
   Identity Response as for an otherwise unknown EAP Extension.
   
   wpa_supplicant handles this slightly differently, if EAP_TNC is defined
   (and it seems to be enabled by default in builds included in standard 
   distros) then in /src/eap_peer/eap_peap.c:640 it calls 
   /src/eap_peer/tncc.c:tncc_process_soh_request() which just calls
   tncc_build_soh() to populate a dummy SoH packet with partially-guessed
   values rather than just dropping through to the default unrecognised-
   packet handling */

static int processExtensionRequest( const CRYPT_SESSION cryptSession, 
									const char *user, const int userLength,
									BYTE *payload, int *bytesCopied )
	{
	int status;

#if 0	/* Display some info on the packets and send a fake response */
	if( !memcmp( payload + 5, "\x00\x01\x37\x00\x00\x00\x22", 7 ) )
		{
		DEBUG_PRINT(( "Server sent Microsoft-proprietary Capabilities "
					  "Negotiation Method Request\n  EAP message " ));
		DEBUG_DUMPHEX( payload, *bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, sending Capabilities Negotiation "
					  "Method Response.\n", *bytesCopied ));
		payload[ 0 ] = 0x02;		/* Convert Request to Response */
		payload[ 15 ] = 0x00;		/* No fragmentation */
		}
	else
		{
		if( !memcmp( payload + 5, "\x00\x01\x37\x00\x00\x00\x21", 7 ) )
			{
			DEBUG_PRINT(( "Server sent Microsoft-proprietary SoH EAP "
						  "Extensions Method Request\n  EAP message " ));
			DEBUG_DUMPHEX( payload, *bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, resending Identity Response.\n",
						  *bytesCopied ));
			
			/* At this point we could in theory send a fake tncc_build_soh()-
			   style response, but for now we just retry the request */
			}
		else
			{
			DEBUG_PRINT(( "Server sent unknown proprietary EAP message\n" ));
			DEBUG_DUMPHEX( payload, *bytesCopied );
			DEBUG_PRINT(( ",\n  , length %d, resending Identity Response.\n",
						  *bytesCopied ));
			}
		payload[ 0 ] = 0x01;	/* Resend identity request */
		memcpy( payload + 1, user, userLength );
		*bytesCopied = 1 + userLength;
		}
#else	/* Just ignore it and repeat our request */
	payload[ 0 ] = 0x01;	/* Resend identity request */
	memcpy( payload + 1, user, userLength );
	*bytesCopied = 1 + userLength;
#endif /* 0 */
	status = cryptPushData( cryptSession, payload, *bytesCopied, 
							bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptPopData( cryptSession, payload, EAP_BUFFER_SIZE, 
						   bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( *bytesCopied < 5 )
		return( CRYPT_ERROR_UNDERFLOW );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Self-Test Routines							*
*																			*
****************************************************************************/

/* Test the implementation using the test vectors from RFC 2759:

	0-to-256-char UserName:
	55 73 65 72													// "User"

	0-to-256-unicode-char Password:
	63 00 6C 00 69 00 65 00 6E 00 74 00 50 00 61 00 73 00 73 00	// "clientPass"

	16-octet AuthenticatorChallenge:
	5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28

	16-octet PeerChallenge:
	21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E

	8-octet Challenge:
	D0 2E 43 86 BC E9 12 26

	16-octet PasswordHash:
	44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE

	24 octet NT-Response:
	82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF

	16-octet PasswordHashHash:
	41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F

	42-octet AuthenticatorResponse:
	"S=407A5589115FD0D6209F510FE9C04566932CDA56" */

static int testMSCHAPv2( void )
	{
	CRYPT_CONTEXT cryptContext;
	const BYTE UserName[] = "\x55\x73\x65\x72";	/* "User" */
	const BYTE Password[] = "\x63\x6C\x69\x65\x6E\x74\x50\x61\x73\x73";
							/* "clientPass" */	
	const BYTE UnicodePassword[] = "\x63\x00\x6C\x00\x69\x00\x65\x00" \
								   "\x6E\x00\x74\x00\x50\x00\x61\x00" \
								   "\x73\x00\x73\x00";
	const BYTE AuthenticatorChallenge[] = \
							"\x5B\x5D\x7C\x7D\x7B\x3F\x2F\x3E" \
							"\x3C\x2C\x60\x21\x32\x26\x26\x28";
	const BYTE PeerChallenge[] = \
							"\x21\x40\x23\x24\x25\x5E\x26\x2A" \
							"\x28\x29\x5F\x2B\x3A\x33\x7C\x7E";
	const BYTE *utf8String = "\x52\xC3\xA9\x73\x75\x6D\xC3\xA9";	/* "Résumé" */
	const BYTE *unicodeString = "\x52\x00\xE9\x00\x73\x00\x75\x00" \
								"\x6D\x00\xE9\x00";
	BYTE unicodePassword[ 256 ], Challenge[ 8 ], PasswordHash[ 16 ];
	BYTE Response[ 24 ];
	int unicodePasswordLength, status;
#if !( defined( _WIN32 ) || defined( _WIN64 ) )
	const char *locale = setlocale( LC_ALL, NULL );

	/* Try and set UTF-8 for the convertToUnicode() self-test.  There's no 
	   portable way to do this since locales are defined in whatever way the 
	   system feels like, but one of the following should give us UTF-8 */
	if( !setlocale( LC_ALL, "en_US.UTF-8" ) && \
		!setlocale( LC_ALL, "en_US.utf8" ) && \
		!setlocale( LC_ALL, "C.UTF-8" ) )
		{
		DEBUG_PUTS(( "Couldn't set locale to UTF-8 for self-test." ));
		return( CRYPT_ERROR_FAILED );
		}
#endif /* !Windows */

	/* Test that the antique crypto that we need for MSCHAPv2 is enabled */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_DES );
	if( cryptStatusError( status ) )
		{
		DEBUG_PUTS(( "Single DES isn't enabled in cryptlib, MSCHAPv2 can't "
					 "be used." ));
		return( CRYPT_ERROR_FAILED );
		}
	cryptDestroyContext( cryptContext );

	/* General test that Unicode conversion is working */
	unicodePasswordLength = convertToUnicode( unicodePassword, 256, 
											  utf8String, 8 );
	if( unicodePasswordLength != 12 || \
		memcmp( unicodePassword, unicodeString, 12 ) )
		{
		DEBUG_PUTS(( "UTF-8 to Windows Unicode conversion via mbstowcs() "
					 "failed." ));
		return( CRYPT_ERROR_FAILED );
		}

#if !( defined( _WIN32 ) || defined( _WIN64 ) )
	setlocale( LC_ALL, locale );
#endif /* !Windows */

	/* Run through each step in GenerateNTResponse() verifying that the 
	   intermediate results are correct */
	unicodePasswordLength = convertToUnicode( unicodePassword, 256, 
											  Password, 10 );
	if( unicodePasswordLength != 20 || \
		memcmp( unicodePassword, UnicodePassword, 20 ) )
		{
		DEBUG_PUTS(( "convertToUnicode test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = ChallengeHash( PeerChallenge, AuthenticatorChallenge,
							UserName, 4, Challenge );
	if( cryptStatusError( status ) || \
		memcmp( Challenge, "\xD0\x2E\x43\x86\xBC\xE9\x12\x26", 8 ) )
		{
		DEBUG_PUTS(( "ChallengeHash test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = NtPasswordHash( UnicodePassword, 20, PasswordHash );
	if( cryptStatusError( status ) || \
		memcmp( PasswordHash, "\x44\xEB\xBA\x8D\x53\x12\xB8\xD6" \
							  "\x11\x47\x44\x11\xF5\x69\x89\xAE", 16 ) )
		{
		DEBUG_PUTS(( "NtPasswordHash test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = ChallengeResponse( Challenge, PasswordHash, Response );
	if( cryptStatusError( status ) || \
		memcmp( Response, "\x82\x30\x9E\xCD\x8D\x70\x8B\x5E" \
						  "\xA0\x8F\xAA\x39\x81\xCD\x83\x54" \
						  "\x42\x33\x11\x4A\x3D\x85\xD6\xDF", 24 ) )
		{
		DEBUG_PUTS(( "ChallengeResponse test failed." ));
		return( CRYPT_ERROR_FAILED );
		}

	/* Now verify that the overall function is correct */
	status = GenerateNTResponse( AuthenticatorChallenge, PeerChallenge, 
								 UserName, 4, UnicodePassword, 20, 
								 Response );
	if( cryptStatusError( status ) || \
		memcmp( Response, "\x82\x30\x9E\xCD\x8D\x70\x8B\x5E" \
						  "\xA0\x8F\xAA\x39\x81\xCD\x83\x54" \
						  "\x42\x33\x11\x4A\x3D\x85\xD6\xDF", 24 ) )
		{
		DEBUG_PUTS(( "GenerateNTResponse test failed.\n" ));
		return( CRYPT_ERROR_FAILED  );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								EAP Interface Routines						*
*																			*
****************************************************************************/

/* Create an EAP-over-TLS session */

static int createEAPsession( CRYPT_SESSION *cryptEAPSession, 
							 const char *server,
							 const char *user, const char *password,
							 const PROTOCOL_TYPE protocolType )
	{
	CRYPT_SESSION cryptSession;
	int status;

	/* Clear return value */
	*cryptEAPSession = -1;

	/* Create the TLS session and set the server to connect to */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
								 CRYPT_SESSION_TLS );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptSetAttributeString( cryptSession, 
									  CRYPT_SESSINFO_SERVER_NAME, 
									  server, strlen( server ) );
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		return( status );
		}

	/* Select EAP-TTLS or PEAP as required */
	switch( protocolType )
		{
		case PROTOCOL_EAPTTLS:
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
										CRYPT_SUBPROTOCOL_EAPTTLS );
			break;

		case PROTOCOL_PEAP:
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
										CRYPT_SUBPROTOCOL_PEAP );
			break;

		default:
			status = CRYPT_ERROR_PARAM5;
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		return( status );
		}

	/* Set the authentication information */
	status = cryptSetAttributeString( cryptSession, 
									  CRYPT_SESSINFO_USERNAME, 
									  user, strlen( user ) );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_PASSWORD, 
										  password, strlen( password ) );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		return( status );
		}

	*cryptEAPSession = cryptSession;
	return( CRYPT_OK );
	}

/* Complete an EAP-TTLS handshake */

static int completeEAPTTLShandshake( const CRYPT_SESSION cryptSession,
									 const char *user, 
									 const char *password,
									 const AUTH_TYPE authType )
	{
	BYTE payload[ EAP_BUFFER_SIZE ], eapChallenge[ 256 ];
	int payloadLength, bytesCopied, eapChallengeLength, status;

	/* Get the EAP challenge value from the session */
	status = cryptGetAttributeString( cryptSession, 
									  CRYPT_SESSINFO_TLS_EAPCHALLENGE, 
									  eapChallenge, &eapChallengeLength );
	if( cryptStatusError( status ) )
		return( status );

	switch( authType )
		{
		case AUTH_PAP:
 			status = createTTLSAVPPAP( payload, EAP_BUFFER_SIZE, 
									   &payloadLength, 
									   user, strlen( user ),
									   password, strlen( password ) );
			break;

		case AUTH_CHAP:
			status = createTTLSAVPCHAP( payload, EAP_BUFFER_SIZE, 
										&payloadLength, 
										user, strlen( user ),
										password, strlen( password ), 
										eapChallenge );
			break;

		case AUTH_MSCHAPV2:
			status = createTTLSAVPMSCHAPv2( payload, EAP_BUFFER_SIZE, 
											&payloadLength,
											user, strlen( user ),
											password, strlen( password ), 
											eapChallenge );
			break;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Send the authentication information to the server */
	status = cryptPushData( cryptSession, payload, payloadLength, 
							&bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's response.  For PAP and CHAP, FreeRADIUS returns a 
	   zero-byte payload, with the response being in the unprotected 
	   RADIUS/EAP wrapper around the EAP-TTLS data (!!).  For MSCHAPv2 we
	   get the Success/Failure message back in TTLS-AVP format */
	status = cryptPopData( cryptSession, payload, EAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( authType == AUTH_MSCHAPV2 )
		{
		/* Read the server's MSCHAPv2 Sucess or Failure Request (in TTLS-AVP 
		   format, i.e. in DIAMETER format):

			uint32	type = 26 / 0x1A	// MSCHAPv2
			byte	flags = FLAG_MANDATORY | FLAG_VENDORIDPRESENT
			uint24	length				// Including header
			uint32	vendorID = 311 / 0x137	// Microsoft
				byte	chapID
				byte[]	authResponse	// "S=<auth_string> M=<message>"
										// "E=eeeeeeeeee R=r C=cccccccccccccccccccccccccccccccc V=vvvvvvvvvv M=<msg>" */
		if( bytesCopied < 12 )
			return( CRYPT_ERROR_UNDERFLOW );
		if( memcmp( payload, "\x00\x00\x00\x1A\xC0", 5 ) || \
			memcmp( payload + 8, "\x00\x00\x01\x37", 4 ) )
			{
			/* We were expecting an MSCHAPv2 response but got something 
			   else */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, 12 );
			DEBUG_PRINT(( ",\n  length 12, expected MSCHAPv2 Response "
						  "message 00 00 00 1A C0 00 nn nn 00 00 01 37.\n" ));
			return( CRYPT_ERROR_BADDATA );
			}
		payload[ bytesCopied ] = '\0';
		DEBUG_PRINT(( "Server responded with MSCHAPv2 message '%s'.\n", 
					  payload + 13 ));
		}
	else
		{
		/* Just in case the server has returned something other than a zero-
		   length respose, we display it for the caller */
		if( bytesCopied > 0 )
			{
			DEBUG_PRINT(( "Server sent %d bytes unexpected data:\n  ", 
						  bytesCopied ));
			DEBUG_DUMPHEX( payload, bytesCopied );
			DEBUG_PRINT(( ".\n" ));
			}
		}

	/* Acknowledge the server's response if required */
	if( authType == AUTH_MSCHAPV2 )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_AUTHRESPONSE, 
									TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Complete a PEAP handshake */

static int completePEAPhandshake( const CRYPT_SESSION cryptSession,
								  const char *user, const char *password )
	{ 
	BYTE payload[ EAP_BUFFER_SIZE ], chapChallenge[ 256 ];
	const int userLength = strlen( user );
	int payloadLength, bytesCopied, chapID, status;

	/* At this point PEAP requires an EAP ACK to be sent in order to 
	   trigger further responses from FreeRADIUS.  If this isn't sent then 
	   the server indicates "eap_peap: PEAP state ?", if it is sent then it 
	   indicates "eap_peap: PEAP state TUNNEL ESTABLISHED" and continues
	   the session.  This is required because PEAP omits the EAP type, ID,
	   and length fields so there's no way for the client to communicate 
	   what it's doing to the server, the only way to continue the protocol
	   is for the server to request things and the client to respond, and to
	   do that it needs to be triggered in some way.

	   This may be an artefact of the FreeRADIUS implementation, since PEAP 
	   can't communicate EAP packets in any normal manner exactly what 
	   happens is very implementation-dependent.  Some diagrams of the PEAP
	   message flow omit this step entirely, some label it "EAP Response",
	   some "EAP Response (PEAP)", and some try and provide an explanation 
	   like "EAP Response Identity to TLS tunnel opened".  All four of these 
	   are different things.
	   
	   The deciding factor seems to be Appendix A of "Microsoft's PEAP 
	   version 0 (Implementation in Windows XP SP1)", which has a 
	   "EAP-Response/EAP-Type=PEAP ->" sent after the TLS handshake has
	   completed, this being the ACK */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_AUTHRESPONSE, 
								TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's Identity Request.  This should be in PEAP format as
	   per "Microsoft's PEAP version 0 (Implementation in Windows XP SP1)",
	   section 1.1, "for EAP Types other than 33, the Code, Identifier, and 
	   Length fields are not sent, but rather EAP packets sent within the 
	   PEAP tunnel begin with the Type field":

		byte	type = 1			// Identity 
	   
	   This is also specified in "[MS-PEAP]: Protected Extensible 
	   Authentication Protocol (PEAP)" section 3.1.5.6 which states that
	   PEAP "compression", stripping the EAP code, packet ID, and length
	   field and leaving only the type and payload, is mandatory for 
	   everything except the Microsoft-specific EAP TLV Extension, 
	   Capabilities Negotiation, and SoH EAP Extensions packets.

	   However FreeRADIUS incorrectly sends the full EAP packet (in EAP 
	   format, code = Request, type = Identity):

		byte	code = 1			// Request
		byte	packet ID			// From the EAP layer below the TLS 
									// tunnel, packet ID there is 5
		uint16	length = 5			// Including header
		byte	type = 1			// Identity
	   
	   See the comment in wpa_supplicant's /src/eap_peer/eap_peap.c:791, 
	   "At least FreeRADIUS seems to send full EAP header with EAP Request 
	   Identity", so we need to be able to deal with either form */
	status = cryptPopData( cryptSession, payload, EAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied == 1 )
		{
		/* PEAP identity request */
		if( payload[ 0 ] != 0x01 )
			{
			/* We were expecting a PEAP Identity Request but got something 
			   else */
			DEBUG_PRINT(( "Server sent %02X, expected PEAP Identity Request "
						  "message 01", payload[ 0 ] ));
			return( CRYPT_ERROR_BADDATA );
			}
		}
	else
		{
		/* FreeRADIUS incorrect EAP identity request */
		if( bytesCopied < 5 )
			return( CRYPT_ERROR_UNDERFLOW );
		if( payload[ 0 ] != 0x01 || payload[ 4 ] != 0x01 )
			{
			/* We were expecting an EAP Identity Request but got something 
			   else */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, expected EAP Identity Request "
						  "message 01 nn 00 05 01.\n", bytesCopied ));
			return( CRYPT_ERROR_BADDATA );
			}
		}

	/* Respond with our Identity (in PEAP format):

		byte	type = 1			// Identity
		byte[]	identity */
#if 0
	/* wpa_supplicant claims that it sends an EAP (rather than PEAP) 
	   response at this point but sending the following to FreeRADIUS 
	   produces:

		eap_peap: Received unexpected EAP-Response, rejecting the session.
		eap_peap: ERROR: Tunneled data is invalid 
	
	   with an Access-Reject sent back to the client.  The error log comes 
	   from FreeRADIUS 3.2.x 
	   src/modules/rlm_eap/types/rlm_eap_peap:eappeap_process() which
	   calls eapmessage_verify() and, for a PW_EAP_RESPONSE packet requires 
	   that it's a PW_EAP_TLV, in other words an extension request 
	   containing some sort of status response to the server.  So 
	   wpa_supplicant can't possibly be sending the message that it claims 
	   it's sending */
	payload[ 0 ] = 0x02;			// Response
	if( bytesCopied <= 1 )
		{
		BYTE eapID;
		int eapIDlength;

		/* We got a PEAP packet, manufacture an EAP packet from the
		   data sent at the outer EAP level */
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_TLS_EAPDATA, 
										  NULL, &eapIDlength );
		if( cryptStatusOK( status ) && eapIDlength != 1 )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status )  )
			{
			status = cryptGetAttributeString( cryptSession, 
											  CRYPT_SESSINFO_TLS_EAPDATA, 
											  &eapID, &eapIDlength );
			}
		if( cryptStatusError( status ) )
			return( status );
		payload[ 1 ] = eapID;
		payload[ 2 ] = 0x00;
		payload[ 3 ] = 5 + userLength;
		payload[ 4 ] = 0x01;
		}
	else
		{
		/* We got an EAP packet, update the header */
		payload[ 3 ] = 5 + userLength;
		}
	memcpy( payload + 5, user, userLength );
	status = cryptPushData( cryptSession, payload, 5 + userLength, 
							&bytesCopied );
#else
	payload[ 0 ] = 0x01;
	memcpy( payload + 1, user, userLength );
	status = cryptPushData( cryptSession, payload, 1 + userLength, 
							&bytesCopied );
#endif
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's MSCHAPv2 Challenge (in PEAP format):

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 1			// Challenge 
		byte	chapID				// Copy to response
		uint16	length == 22 + nLen	// Including header
		byte	value-size = 16 / 0x10	// Fixed at 16 bytes
			byte[16]	chapChallenge// Challenge 
		byte[]	name				// Remaining bytes = server name */
	status = cryptPopData( cryptSession, payload, EAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 5 )
		return( CRYPT_ERROR_UNDERFLOW );
	while( bytesCopied >= 12 && \
		   payload[ 0 ] == 0x01 && payload[ 4 ] == 0xFE )
		{
		/* At this point Microsoft servers may send back one or more 
		   extension requests, this time in EAP rather than PEAP format, 
		   with the 12-byte EAP extension header followed by the payload:

			byte	code = 1		// Request
			byte	packet ID
			uint16	length			// Including header
			byte	type = 254		// Expanded Types
			uint24	vendorID		
			uint32	vendorType
			...

		   using Microsoft-proprietary attributes and contents.  In order to 
		   continue we have to work our way past these, so we keep reading
		   extension requests until we get to something else */
		status = processExtensionRequest( cryptSession, user, userLength, 
										  payload, &bytesCopied );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( bytesCopied < 22 || \
		payload[ 0 ] != 0x1A || payload[ 1 ] != 0x01 || payload[ 5 ] != 0x10 )
		{
		/* We were expecting an MSCHAPv2 Challenge but got something else */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, expected MSCHAPv2 Challenge message "
					  "1A 01 nn 00 nn 10...\n", bytesCopied ));
		return( CRYPT_ERROR_BADDATA );
		}
	memcpy( chapChallenge, payload + 6, 16 );
	chapID = payload[ 2 ] & 0xFF;

	/* Respond with our MSCHAPv2 Response (in PEAP format) */
	status = createPEAPAVPMSCHAPv2( payload, EAP_BUFFER_SIZE, &payloadLength,
									user, userLength,
									password, strlen( password ), 
									chapChallenge, chapID );
	if( cryptStatusOK( status ) )
		{
		status = cryptPushData( cryptSession, payload, payloadLength, 
								&bytesCopied );
		}
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's MSCHAPv2 Success or Failure Request (in PEAP format):

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 3			// Success Request
		byte	MSCHAPv2ID
		uint16	length
		byte[]	authResponse		// "S=<auth_string> M=<message>"

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 4			// Failure Request
		byte	MSCHAPv2ID
		uint16	length
		byte[]	authResponse		// "E=eeeeeeeeee R=r C=cccccccccccccccccccccccccccccccc V=vvvvvvvvvv M=<msg>" 

	   The opcodes for these packets are actually 3 = Success and 4 = Failure, 
	   however when sent from the server they're Success/Failure Request and 
	   when sent back from the client they're Success/Failure Response.
	   
	   For the errors, E is a typically 3-digit error code, R is 1 if 
	   request retries are allowed, C is a new 16-digit challenge for the
	   retried request, and V is the MSCHAP version supported on the server.
	   With true Microsoft logic, for MSCHAPv2 the version value is 3 (RFC 
	   2759 section 6).

	   The documented error codes, from RFC 2759, are:

		646 ERROR_RESTRICTED_LOGON_HOURS
		647 ERROR_ACCT_DISABLED
		648 ERROR_PASSWD_EXPIRED
		649 ERROR_NO_DIALIN_PERMISSION
		691 ERROR_AUTHENTICATION_FAILURE
		709 ERROR_CHANGING_PASSWORD

	   In the case of "E=691 R=1" this technically means "The remote 
	   connection was denied because the user name and password combination 
	   you provided is not recognized, or the selected authentication 
	   protocol is not permitted on the remote access server" however in 
	   practice it's a more generic "Something went wrong".  In particular 
	   MSCHAPv2 uses NTLMv1 when used in Windows RAS services, but this
	   is usually disabled on DCs with only NTLMv2 being enabled.  The fix
	   is to enable NTLMv2 for MSCHAPv2 as per
	   https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/rras-vpn-connections-fail-ms-chapv2-authentication

	   This may also be affected by the LmCompatibilityLevel setting on
	   the DC, see
	   https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960646(v=technet.10)
	   */
	status = cryptPopData( cryptSession, payload, EAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 5 )
		return( CRYPT_ERROR_UNDERFLOW );
	if( payload[ 0 ] != 0x1A || \
		( payload[ 1 ] != 0x03 && payload[ 1 ] != 0x04 ) )
		{
		/* We were expecting an MSCHAPv2 Success Request but got something 
		   else */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, expected MSCHAPv2 Success/Failure "
					  "Request message 1A 03 nn 00 nn... or 1A 04 nn 00 "
					  "nn...\n", bytesCopied ));

		/* In the case of an invalid user name we get back an EAP Extension 
		   Request (in EAP format):

			byte	type = 1		// Identity Request
			byte	packet ID		// From the EAP layer below the TLS 
									// tunnel, packet ID there is 7 so this
									// will be 8
			uint16	length = 11 / 0x0B	// Including header
			byte	type = 33 / 0x21	// EAP Extensions / PW_EAP_TLV
				byte	ext.flags = 0x80// TLV flags, mandatory AVP
				byte	ext.type = 3	// TLV type, Result = 3 / EAP_TLV_ACK_RESULT
				uint16	ext.length = 2	// TLV length
				uint16	status = 2		// TLV data, Failure = 2 / EAP_TLV_FAILURE

		   This differs from EAP-TTLS where a message with an unknown 
		   Identity is rejected at the RADIUS/EAP level because in PEAP the 
		   real identity is conveyed over the PEAP tunnel, with the one 
		   given at the RADIUS/EAP level typically being something like 
		   "anonymous".

		   In the case of FreeRADIUS the implementation is in 
		   /src/modules/rlm_eap/types/rlm_eap_peap/peap.c function 
		   eappeap_failure(), but other servers like Microsoft's NPS do the 
		   same thing */
		if( bytesCopied >= 11 && \
			payload[ 0 ] == 0x01 && payload[ 4 ] == 0x21 && \
			payload[ 6 ] == 0x03 && payload[ 10 ] == 0x02 )
			{
			/* There isn't really an appropriate error code for incorrect-
			   username so the best that we can report is a 
			   CRYPT_ERROR_WRONGKEY, in the sense of "wrong credentials" */
			DEBUG_PUTS(( "Server sent Identity Request - EAP Extension - "
						 "Failure, indicating an incorrect user name." ));
			return( CRYPT_ERROR_WRONGKEY );
			}

		return( CRYPT_ERROR_BADDATA );
		}
	payload[ bytesCopied ] = '\0';
	if( payload[ 1 ] == 0x03 )
		{
		DEBUG_PRINT(( "Server responded with Success packet, message "
					  "'%s'.\n", payload + 5 ));
		}
	else
		{
		DEBUG_PRINT(( "Server responded with Failure packet, message "
					  "'%s'.\n", payload + 5 ));
		}

	/* Send our MSCHAPv2 Success/Failure Response (in PEAP format):

		byte	type = 26 / 0x1A		// MSCHAPv2
		byte	opcode = 3				// Success Response

		byte	type = 26 / 0x1A		// MSCHAPv2
		byte	opcode = 4				// Failure Response 

	   In essence this just consists of echoing the first two bytes of the 
	   received packet back to the server */
	status = cryptPushData( cryptSession, payload, 2, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* At this point the negotiation should be complete, however FreeRADIUS
	   continues with EAP (not PEAP) messages, which we need to deal with in
	   order to get RADIUS attributes back.  This is based on the 
	   "Microsoft's PEAP version 0 Implementation in Windows XP SP1" draft
	   (draft-kamath-pppext-peapv0-00.txt), section 1.3 which specifies it 
	   as required for Windows XP SP1 compatibility, and see also the note 
	   earlier on why the EAP format is used.  
	   
	   Microsoft documents it differently in "[MS-CHAP]: Extensible 
	   Authentication Protocol Method for Microsoft Challenge Handshake 
	   Authentication Protocol (CHAP)", stating that what's sent back is an
	   EAP Success packet, however what it calls "EAP Success" is actually 
	   an Extension Request containing a Success status.
	   
	   Cisco also apparently sends extensions at this point, specifically an
	   ACK Result which we just echo back with the first byte changed to 02,
	   Response */

	/* Read the server's Extension Request (in EAP format, code = Request, 
	   type = Extension, type names from FreeRADIUS).  The following is from 
	   draft-kamath-pppext-peapv0-00.txt mentioned above, section 2, which 
	   defines Extension Request/Response packets, type = 33, for which the 
	   only valid TLV type is 3, "Acknowledged Result".  So essentially the 
	   entire packet is fixed boilerplate except for the last byte, which is 
	   either "1 - Success", or "2 - Failure".

		byte	code = 1			// Request / PW_EAP_REQUEST
		byte	packet ID			// From the EAP layer below the TLS 
									// tunnel, packet ID there is 7 so this 
									// will be 8
		uint16	length = 17 / 0x11	// Including header
		byte	type = 33 / 0x21	// EAP Extensions, from PEAP RFC / PW_EAP_TLV
			byte	ext.flags = 0x80// TLV flags, mandatory AVP
			byte	ext.type = 3	// TLV type, Result = 3 / EAP_TLV_ACK_RESULT
			uint16	ext.length = 2	// TLV length
			uint16	status = 1		// TLV data, Success = 1 / EAP_TLV_SUCCESS,
									//			 Failure = 2 / EAP_TLV_FAILURE

	   The AVP format is actually a single-bit flag for mandatory/optional,
	   a zero bit, and then 14 bits of type, but only the value 3 is 
	   defined for the type (see above) so we treat it as two bytes, one with 
	   flags and one with the type */
	status = cryptPopData( cryptSession, payload, EAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 11 )
		return( CRYPT_ERROR_UNDERFLOW );
	if( payload[ 0 ] != 0x01 || payload[ 4 ] != 0x21 || \
		payload[ 6 ] != 0x03 )
		{
		/* We were expecting another Identity Request but got something 
		   else */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, expected EAP Identity Request - "
					  "Acknowledged Result - Success message 01 nn 00 11 "
					  "21 80 03 00 02 00 01.\n", bytesCopied ));
		return( CRYPT_ERROR_BADDATA );
		}
	if( payload[ 10 ] == 0x01 )
		{
		DEBUG_PRINT(( "Server responded with Acknowledged Result - Success "
					  "packet.\n" ));
		}
	else
		{
		DEBUG_PRINT(( "Server responded with Acknowledged Result - Failure "
					  "packet.\n" ));

		/* This isn't a CRYPT_ERROR_WRONGKEY because the authentication has
		   already succeeded, the only reason why we'd get a failure 
		   response at this point is because of a server error where it 
		   can't continue for some reason */
		return( CRYPT_ERROR_BADDATA );
		}

	/* The NPS negotiation ends at this point, sending an Extension Response 
	   as we do for FreeRADIUS results in a "Received Crypto-Binding TLV is 
	   invalid" error which appears to be caused by having the "Disconnect 
	   Clients Without Cryptobinding" option set on the server so that it 
	   expects a Crypto-Binding but doesn't see one.  The Crypto-Binding 
	   doesn't exist in the PEAP version used here, PEAPv0, but was added in 
	   PEAPv2 ("Protected EAP Protocol (PEAP) Version 2", section 4.5), so 
	   it's unclear on what basis NPS requires that it be present in a 
	   PEAPv0 exchange, but in any case it should be disabled by unsetting
	   "Disconnect Clients Without Cryptobinding" */

	/* Convert the previous Extension Request into an Extension Response (in 
	   EAP format, code = Response, type names from FreeRADIUS):

		byte	code = 2			// Response / PW_EAP_RESPONSE
		[ Rest as above ] 

	   This is as per the PEAP-kludges RFC mentioned above 
	   (draft-kamath-pppext-peapv0-00.txt), section 3.2, which says that for 
	   Windows use support for the Result AVP is required, with the only 
	   allowed message being EAP Request, type = Extensions, status = 
	   Success answered by EAP Response, type = Extensions, status = 
	   Success.  Anything else should be treated as a failure.  FreeRADIUS 
	   implements this by only checking that the code is PW_EAP_RESPONSE, 
	   the type is PW_EAP_TLV, and the status is EAP_TLV_SUCCESS */
	payload[ 0 ] = 0x02;
	status = cryptPushData( cryptSession, payload, bytesCopied, 
							&bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read an empty response from the server.  This is used to communicate 
	   the RADIUS attributes outside the tunnel (because why send them in the
	   secure tunnel when you can include them unsecured outside it?), so 
	   presumably the PEAP payload is just a no-op */
	status = cryptPopData( cryptSession, payload, EAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied != 0 )
		{
		/* This should be a zero-length EAP message */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, should have been zero-length "
					  "message.\n", bytesCopied ));
		return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
	}

/* Get any additional data that may have been provided by the server */

static int getExtraData( const CRYPT_SESSION cryptSession,
						 BYTE *data, int *dataLen, const int dataMaxLen )
	{
	int extraDataLength, status;

	/* Get any extra data that may be present */
	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPDATA, 
									  NULL, &extraDataLength );
	if( cryptStatusError( status ) )
		return( status );
	if( extraDataLength > dataMaxLen )
		return( CRYPT_ERROR_OVERFLOW );
	return( cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPDATA, 
									 data, dataLen ) );
	}

/****************************************************************************
*																			*
*								EAP Test Functions							*
*																			*
****************************************************************************/

typedef enum { TEST_NORMAL, TEST_WRONGUSER, TEST_WRONGPASSWORD, 
			   TEST_LAST } TEST_TYPE;

/* Text descriptions of the different sub-protocols and authentication 
   types.  These must match the corresponding PROTOCOL_xxx/AUTH_xxx values */

static const char *protocolName[] = {
	"EAP-TTLS", "PEAP", "<<<Unknown>>>", "<<<Unknown>>>"
	};
static const char *authName[] = {
	"PAP", "CHAP", "MSCHAPv2", "<<<Unknown>>>", "<<<Unknown>>>"
	};

/* Helper function to dump hex data */

#ifndef NDEBUG

static void dumpHexData( const BYTE *data, const int dataLen )
	{
	int i;

	/* If it's 32 bytes or less then we output the entire quantity */
	if( dataLen <= 32 )
		{

		for( i = 0; i < dataLen - 1; i++ )
			printf( "%02X ", data[ i ] );
		printf( "%02X", data[ i ] );
		
		return;
		}

	/* It's more than 32 bytes, only output the first and last 16 bytes */
	for( i = 0; i < 16; i++ )
		printf( "%02X ", data[ i ] );
	printf( "... " );
	for( i = dataLen - 16; i < dataLen - 1; i++ )
		printf( "%02X ", data[ i ] );
	printf( "%02X", data[ dataLen - 1 ] );
	}
#endif /* !NDEBUG */

/* Test an EAP subprotocol, either EAP-TTLS (PAP, CHAP, or MSCHAPv2) or PEAP 
   (MSCHAPv2), with various EAP authentication types and correct or 
   incorrect parameters */

static int testEAPSubprotocol( const PROTOCOL_TYPE protocolType, 
							   const AUTH_TYPE authType,
							   const TEST_TYPE testType )
	{
	CRYPT_SESSION cryptSession;
	const char *serverName, *password;
	const char *user = "test321";
	const char *radiusSecret = "dummy";
	const PROTOCOL_TYPE localProtocolType = \
							( protocolType == PROTOCOL_PEAP_NPS ) ? \
							  PROTOCOL_PEAP : protocolType; 
	BYTE dataBuffer[ 128 ];
	int dataLength, status, extraDataStatus;

	/* Make sure that a valid test has been selected */
	switch( protocolType )
		{
		case PROTOCOL_EAPTTLS:
			/* XU4, EAP-TTLS on FreeRADIUS */
			serverName = "odroid.xu4.lan:1812";
			password = "testing123";
			break;

		case PROTOCOL_PEAP:
			/* N2, PEAP on FreeRADIUS */
			serverName = "odroid.n2.lan:1812";
			password = "testing123";
			break;

		case PROTOCOL_PEAP_NPS:
			/* NPS, PEAP on NPS with password-complexity requirements that 
			   disallow the use of the standard test password */
			serverName = "101.100.138.250:1812";
			password = "Slipper520#Couch";
			break;

		default:
			puts( "Invalid protocol type." );
			return( FALSE );
		}

	if( authType >= AUTH_LAST )
		{
		puts( "Invalid auth type." );
		return( FALSE );
		}

	/* Set up the required test parameters */
	switch( testType )
		{
		case TEST_NORMAL:
			break;

		case TEST_WRONGUSER:
			user = "wrongUsername";
			break;

		case TEST_WRONGPASSWORD:
			password = "wrongPassword";
			break;

		default:
			puts( "Invalid test type." );
			return( FALSE );
		}

	/* Run a self-test of the MSCHAPv2 code to verify that we're getting the 
	   correct values */
	status = testMSCHAPv2();
	if( cryptStatusError( status ) )
		{
		printf( "MSCHAPv2 self-test failed, status = %d.\n", status );
		return( FALSE );
		}

	/* Report what we're doing */
	printf( "Connecting to %s using %s/%s, user = %s, password = %s,\n"
			"  RADIUS secret = %s.\n", serverName, 
			protocolName[ localProtocolType ], authName[ authType ], user, 
			password, radiusSecret );

	/* Create the EAP session */
	status = createEAPsession( &cryptSession, serverName, user, 
							   radiusSecret, localProtocolType );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to create EAP session failed, status %d.\n", 
				status );
		return( FALSE );
		}

	/* No 2.x version of FreeRADIUS and no 3.x version before about 3.10
	   supported TLS 1.2 or even 1.1, returning weird errors if newer 
	   versions of TLS were attempted.  To deal with this, undefine the 
	   following, which forces use of TLS 1.0 in order to deal with older
	   FreeRADIUS implementations */
#if 0
	cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION, 1 );
#endif /* 0 */

	/* Disable name verification to allow the test server's self-signed RFC 
	   1918 address cert to work */
	cryptSetAttribute( cryptSession, CRYPT_SESSINFO_TLS_OPTIONS, 
					   CRYPT_TLSOPTION_DISABLE_NAMEVERIFY );

	/* Activate the EAP-TTLS or PEAP tunnel.  cryptlib sends the identity
	   in the outermost RADIUS tunnel as "anonymous" as required by several
	   usage documents, this is allowed by default by FreeRADIUS but not 
	   Windows NPS which will need to have the "Enable Identity Privacy" 
	   setting enabled, see
	   https://learn.microsoft.com/en-us/archive/blogs/wsnetdoc/peap-identity-privacy-support-in-windows-7-and-windows-server-2008-r2 
	   https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff919512(v=ws.10) */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		const int networkStatus = status;
		int errorMessageLength;

		printf( "Session activation failed with error code %d.\n", status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );
		if( networkStatus == CRYPT_ERROR_TIMEOUT && \
			!strcmp( password, radiusSecret ) )
			{
			/* EAP-over-RADIUS requires that all RADIUS messages contain a 
			   Message-Authenticator attribute, with packets with an 
			   incorrect HMAC-MD5 authentication value being silently 
			   dropped.  If the authenticator is also the user's password, 
			   an incorrect password will result in no response from the 
			   server until a timeout is triggered rather than an incorrect-
			   password response.  
			   
			   This totally stupid behaviour is mandated in RFC 3579, 
			   section 3.2: "[The Message-Authenticator] MUST be used in any 
			   Access-Request, Access-Accept, Access-Reject or Access-
			   Challenge that includes an EAP-Message attribute.  A RADIUS 
			   server receiving an Access-Request with a Message-
			   Authenticator attribute present MUST calculate the correct 
			   value of the Message-Authenticator and silently discard the 
			   packet if it does not match the value sent".  
			   
			   To deal with this, we report a CRYPT_ERROR_TIMEOUT as a 
			   possible incorrect password */
			puts( "  The network timeout may be due to an incorrect "
				  "password rather than an\n  actual networking problem, "
				  "since RADIUS silently drops packets\n  authenticated "
				  "with incorrect passwords rather than returning an "
				  "error\n  response.  In other words no response will be "
				  "received from the server if\n  an incorrect password is "
				  "used.\n" );
			}
 		cryptDestroySession( cryptSession );
		return( FALSE );
		}

	/* At this point PEAP and EAP-TTLS diverge, so we complete the handshake
	   as required */
	if( localProtocolType == PROTOCOL_PEAP )
		{
		/* PEAP uses a format that Microsoft invented (or more accurately 
		   that's probably an implementation bug from Windows 2000), we 
		   can't continue with the standard EAP process but have to move to 
		   a PEAP-specific one.  PEAP, or specifically Microsoft's PEAPv0 
		   which is what everything uses, is really only defined for 
		   MSCHAPv2, so the following function continues with MSCHAPv2 
		   implied */
		status = completePEAPhandshake( cryptSession, user, password );
		}
	else
		{
		status = completeEAPTTLShandshake( cryptSession, user, password, 
										   authType );
		}
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		const int networkStatus = status;
		int errorMessageLength;

		printf( "%s authentication failed with error code %d.\n", 
				protocolName[ localProtocolType ], status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );

		/* Restore the previous status value */
		status = networkStatus;
		}

	/* Display any extra data that the server may have sent */
	extraDataStatus = getExtraData( cryptSession, dataBuffer, &dataLength, 
									512 );
	if( cryptStatusOK( extraDataStatus ) )
		{
		printf( "Server sent %d bytes additional data:\n  ", dataLength );
		DEBUG_DUMPHEX( dataBuffer, dataLength );
		printf( ".\n" );
		}

	/* Clean up */
	cryptDestroySession( cryptSession );
	printf( "Authentication status = %d.\n", status );

	return( TRUE );
	}

int testEAP( void )
	{
#if 0
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_PAP, TEST_NORMAL );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_PAP, TEST_WRONGUSER );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_PAP, TEST_WRONGPASSWORD );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_CHAP, TEST_NORMAL );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_MSCHAPV2, TEST_NORMAL );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_MSCHAPV2, TEST_WRONGPASSWORD );
#endif /* EAP-TTLS */
#if 1
	testEAPSubprotocol( PROTOCOL_PEAP, AUTH_MSCHAPV2, TEST_NORMAL );
	testEAPSubprotocol( PROTOCOL_PEAP, AUTH_MSCHAPV2, TEST_WRONGUSER );
	testEAPSubprotocol( PROTOCOL_PEAP, AUTH_MSCHAPV2, TEST_WRONGPASSWORD );
#endif /* PEAP */
#if 0
	testEAPSubprotocol( PROTOCOL_PEAP_NPS, AUTH_MSCHAPV2, TEST_NORMAL );
	testEAPSubprotocol( PROTOCOL_PEAP_NPS, AUTH_MSCHAPV2, TEST_WRONGUSER );
	testEAPSubprotocol( PROTOCOL_PEAP_NPS, AUTH_MSCHAPV2, TEST_WRONGPASSWORD );
#endif /* PEAP to Windows NPS */

	return( TRUE );
	}

#if 0	/* main() when used as a standalone application */

int main( int argc, char **argv )
	{
	int status;

	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "cryptInit() failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}

	testEAP();

	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		printf( "cryptEnd() failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}

	return( EXIT_SUCCESS );
	}
#endif /* 0 */

#endif /* USE_EAP */
