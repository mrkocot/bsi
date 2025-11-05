/****************************************************************************
*																			*
*							cryptlib TPM Routines							*
*						Copyright Peter Gutmann 2020-2022					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "device.h"
  #include "tss2_fapi.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/device.h"
  #include "device/tss2_fapi.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/misc_rw.h"
#endif /* Compiler-specific includes */

#ifdef USE_TPM

#if defined( _MSC_VER )
  #pragma message( "  Building with TPM device interface enabled." )
#endif /* Warn with VC++ */

/* The path on which Fapi_Get/SetAppData() stores data. The FAPI spec
   defines paths for keys, NV data, and policies, but not application data,
   the following follows the general pattern set for this, <type> ||
   <vendor/application> */

#define FAPI_APPDATA_PATH	"/appdata/cryptlib"

/* The size of the local buffer used to store TPM-related data.  This is a
   memory-mapped PKCS #15 keyset that's used to store certificates and
   indexing information required to work with private keys in the TPM */

#define TPM_BUFFER_SIZE		8192

/* There's no readily-available FAPI driver under Windows so we have to
   emulate the FAPI functions that are available under Unix.  This 
   capability also makes debugging under Unix easier when it's not
   necessary to reset the TPM on each run */

#ifdef __WINDOWS__
  #define USE_TPM_EMULATION
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 	Driver Load/Unload Routines						*
*																			*
****************************************************************************/

/* Whether the TPM FAPI library has been initialised or not, this is
   initialised on demand the first time that it's accessed */

static BOOLEAN tpmInitialised = FALSE;

/* Depending on whether we're running under Windows or Unix we load the 
   device driver under a different name */

#ifdef __WINDOWS__
  #define TPM_LIBNAME		"libtss2-fapi.dll"
#else
  #define TPM_LIBNAME		"libtss2-fapi.so"
#endif /* __WINDOWS__ */

#ifndef USE_TPM_EMULATION

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   driver libraries.  Explicitly linking to them will make cryptlib 
   unloadable on most systems */

static INSTANCE_HANDLE hTPM = NULL_INSTANCE;

typedef TSS2_RC ( *FAPI_CREATEKEY )( FAPI_CONTEXT *context, char const *path, 
									 char const *type, 
									 char const *policyPath, 
									 char const *authValue );
typedef TSS2_RC ( *FAPI_DECRYPT )( FAPI_CONTEXT *context, char const *keyPath, 
								   uint8_t const *cipherText, 
								   size_t cipherTextSize, uint8_t **plainText, 
								   size_t *plainTextSize );
typedef TSS2_RC ( *FAPI_DELETE )( FAPI_CONTEXT *context, 
								  char const *path );
typedef void ( *FAPI_FINALIZE )( FAPI_CONTEXT **context );
typedef void ( *FAPI_FREE )( void *ptr );
typedef TSS2_RC ( *FAPI_GETAPPDATA )( FAPI_CONTEXT *context,
									  char const *path,
									  uint8_t **appData,
									  size_t *appDataSize );
typedef TSS2_RC ( *FAPI_GETINFO )( FAPI_CONTEXT *context, char **info );
typedef TSS2_RC ( *FAPI_GETRANDOM )( FAPI_CONTEXT *context, size_t numBytes, 
									 uint8_t **data );
typedef TSS2_RC ( *FAPI_GETTPMBLOBS )( FAPI_CONTEXT *context, char const *path, 
									   uint8_t **tpm2bPublic, 
									   size_t *tpm2bPublicSize, 
									   uint8_t **tpm2bPrivate, 
									   size_t *tpm2bPrivateSize, 
									   char **policy );
typedef TSS2_RC ( *FAPI_INITIALIZE )( FAPI_CONTEXT **context, 
									  char const *uri );
typedef TSS2_RC ( *FAPI_PROVISION )( FAPI_CONTEXT *context, 
									 const char *authValueEh,
									 const char *authValueSh, 
									 const char *authValueLockout );
typedef TSS2_RC ( *FAPI_SETAPPDATA )( FAPI_CONTEXT *context,
									  char const *path,
									  uint8_t const *appData,
									  size_t appDataSize );
typedef TSS2_RC ( *FAPI_SIGN )( FAPI_CONTEXT *context, char const *keyPath, 
								char const *padding, uint8_t const *digest, 
								size_t digestSize, uint8_t **signature, 
								size_t *signatureSize, char **publicKey, 
								char **certificate );

static FAPI_CREATEKEY pFapi_CreateKey = NULL;
static FAPI_DECRYPT pFapi_Decrypt = NULL;
static FAPI_DELETE pFapi_Delete = NULL;
static FAPI_FINALIZE pFapi_Finalize = NULL;
static FAPI_FREE pFapi_Free = NULL;
static FAPI_GETAPPDATA pFapi_GetAppData = NULL;
static FAPI_GETINFO pFapi_GetInfo = NULL;
static FAPI_GETRANDOM pFapi_GetRandom = NULL;
static FAPI_GETTPMBLOBS pFapi_GetTpmBlobs = NULL;
static FAPI_INITIALIZE pFapi_Initialize = NULL;
static FAPI_PROVISION pFapi_Provision = NULL;
static FAPI_SETAPPDATA pFapi_SetAppData = NULL;
static FAPI_SIGN pFapi_Sign = NULL;

/* Dynamically load the TPM drivers.  These are quite buggy and will often 
   segfault or similar on load, which is a problem because it appears that
   it's cryptlib that's segfaulting rather than the buggy driver.  To deal
   with this we install a signal handler to catch segfaults and report that
   it's a problem with the driver */

#if defined( __UNIX__ ) && defined( __linux__ )

#include <signal.h>

struct sigaction oldAction;

void segfaultHandler( int signal )
	{
	static const char *message = \
		"\nError: TPM driver '" TPM_LIBNAME "' segfaulted on load.  To "
		"allow\ncryptlib to run, either disable the buggy TPM driver or "
		"build cryptlib\nwithout USE_TPM defined.\n\n";

	/* Tell the user what went wrong.  We use purely POSIX.1 async-signal-
	   safe functions to make sure that we don't run into any complications, 
	   although since we're in the process of fatally crashing anyway it's 
	   not clear how much more trouble we can actually get into */
	( void ) write( 2, message, strlen( message ) );
	exit( EXIT_FAILURE );
	}
static void setSegfaultHandler( void )
	{
	struct sigaction sigAction;

	memset( &sigAction, 0, sizeof( struct sigaction ) );
	sigAction.sa_handler = segfaultHandler;
	sigemptyset( &sigAction.sa_mask );
	sigaction( SIGSEGV, &sigAction, &oldAction );
	}
static void resetSegfaultHandler( void )
	{
	sigaction( SIGSEGV, &oldAction, NULL );
	}
#else
  #define setSegfaultHandler()
  #define resetSegfaultHandler()
#endif /* Linux */

static int initCapabilities( void );

CHECK_RETVAL \
int deviceInitTPM( void )
	{
	/* Obtain a handle to the device driver module.  Since the buggy TPM 
	   drivers can segfault on load we add extra handling around this if
	   possible */
	DEBUG_DIAG(( "Attempting to load TPM driver '" TPM_LIBNAME "'.  If this "
				 "segfaults then there's a problem with the driver." ));
	setSegfaultHandler();
	hTPM = DynamicLoad( TPM_LIBNAME );
	resetSegfaultHandler();
	if( hTPM == NULL_INSTANCE )
		{
		DEBUG_DIAG(( "Couldn't load TPM driver '" TPM_LIBNAME "'" ));
		return( CRYPT_ERROR );
		}
	DEBUG_DIAG(( "Loaded TPM driver '" TPM_LIBNAME "'" ));

	/* Now get pointers to the functions */
	pFapi_CreateKey = ( FAPI_CREATEKEY ) DynamicBind( hTPM, "Fapi_CreateKey" );
	pFapi_Decrypt = ( FAPI_DECRYPT ) DynamicBind( hTPM, "Fapi_Decrypt" );
	pFapi_Delete = ( FAPI_DELETE ) DynamicBind( hTPM, "Fapi_Delete" );
	pFapi_Finalize = ( FAPI_FINALIZE ) DynamicBind( hTPM, "Fapi_Finalize" );
	pFapi_Free = ( FAPI_FREE ) DynamicBind( hTPM, "Fapi_Free" );
	pFapi_GetAppData = ( FAPI_GETAPPDATA ) DynamicBind( hTPM, "Fapi_GetAppData" );
	pFapi_GetInfo = ( FAPI_GETINFO ) DynamicBind( hTPM, "Fapi_GetInfo" );
	pFapi_GetRandom = ( FAPI_GETRANDOM ) DynamicBind( hTPM, "Fapi_GetRandom" );
	pFapi_GetTpmBlobs = ( FAPI_GETTPMBLOBS ) DynamicBind( hTPM, "Fapi_GetTpmBlobs" );
	pFapi_Initialize = ( FAPI_INITIALIZE ) DynamicBind( hTPM, "Fapi_Initialize" );
	pFapi_Provision = ( FAPI_PROVISION ) DynamicBind( hTPM, "Fapi_Provision" );
	pFapi_SetAppData = ( FAPI_SETAPPDATA ) DynamicBind( hTPM, "Fapi_SetAppData" );
	pFapi_Sign = ( FAPI_SIGN ) DynamicBind( hTPM, "Fapi_Sign" );

	/* Make sure that we got valid pointers for every device function */
	if( pFapi_CreateKey == NULL || pFapi_Decrypt == NULL || \
		pFapi_Delete == NULL || pFapi_Finalize == NULL || \
		pFapi_Free == NULL || pFapi_GetAppData || pFapi_GetInfo == NULL || \
		pFapi_GetRandom == NULL || pFapi_GetTpmBlobs == NULL || \
		pFapi_Initialize == NULL || pFapi_Provision == NULL || \
		pFapi_SetAppData == NULL || pFapi_Sign == NULL )
		{
		/* Free the library reference and reset the handle */
		DynamicUnload( hTPM );
		hTPM = NULL_INSTANCE;
		return( CRYPT_ERROR_OPEN );
		}

	return( CRYPT_OK );
	}

void deviceEndTPM( void )
	{
	if( hTPM != NULL_INSTANCE )
		DynamicUnload( hTPM );
	hTPM = NULL_INSTANCE;
	}
#endif /* USE_TPM_EMULATION */

/****************************************************************************
*																			*
*						 		TPM Emulation Layer							*
*																			*
****************************************************************************/

/* TPM emulation layer that emulates the FAPI calls without requiring the
   enormously complex and awkward TPM drivers and configuration to be 
   present */

#ifdef USE_TPM_EMULATION 

/* Emulation of FAPI functions */

static INSTANCE_HANDLE hTPM = ( INSTANCE_HANDLE  ) "";
static CRYPT_CONTEXT rsaContext = CRYPT_ERROR;

int deviceInitTPM( void )
	{
	DEBUG_DIAG(( "Faking load of TPM driver '" TPM_LIBNAME "'" ));
	return( CRYPT_OK );
	}
void deviceEndTPM( void )
	{
	}

TSS2_RC pFapi_CreateKey( FAPI_CONTEXT *context, char const *path, 
						 char const *type, 
						 char const *policyPath, 
						 char const *authValue )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	FILE *filePtr;
	const int keySize = bitsToBytes( 2048 );
	int status;

	filePtr = fopen( "/tmp/tpmkey.dat", "wb" );
	if( filePtr == NULL )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
	fwrite( path, strlen( path ), 1, filePtr );
	fclose( filePtr );

	/* Create an RSA context to use to emulate the required RSA operations */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_RSA );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( TSS2_FAPI_RC_NO_DECRYPT_PARAM );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
					 ( MESSAGE_CAST ) &keySize, CRYPT_CTXINFO_KEYSIZE );
	setMessageData( &msgData, "TMP Key", 7 );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S, 
					 &msgData, CRYPT_CTXINFO_LABEL );
	status = krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_CTX_GENKEY );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( TSS2_RC_SUCCESS + 1 );
		}
	rsaContext = createInfo.cryptHandle;

	return( TSS2_RC_SUCCESS );
	}

TSS2_RC pFapi_Decrypt( FAPI_CONTEXT *context, char const *keyPath, 
					   uint8_t const *cipherText, size_t cipherTextSize, 
					   uint8_t **plainText, size_t *plainTextSize )
	{
	static BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int status;

	memcpy( buffer, cipherText, cipherTextSize );
	status = krnlSendMessage( rsaContext, IMESSAGE_CTX_DECRYPT, buffer,
							  cipherTextSize );
	if( cryptStatusError( status ) )
		return( TSS2_RC_SUCCESS + 1 );
	*plainText = buffer;
	*plainTextSize = cipherTextSize;

	return( TSS2_RC_SUCCESS );
	}

TSS2_RC pFapi_Delete( FAPI_CONTEXT *context, char const *path )
	{
	if( remove( "/tmp/tpmkey.dat" ) )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );

	krnlSendNotifier( rsaContext, IMESSAGE_DECREFCOUNT );
	rsaContext = CRYPT_ERROR;
	return( TSS2_RC_SUCCESS );
	}

void pFapi_Finalize( FAPI_CONTEXT **context )
	{
	}

void pFapi_Free( void *ptr )
	{
	/* Emulated data structures are statically allocated so there's nothing 
	   to free */
	}

TSS2_RC pFapi_GetAppData( FAPI_CONTEXT *context, char const *path,
						  uint8_t **appData, size_t *appDataSize )
	{
	FILE *filePtr;
	long dataSize;
	int count;

	filePtr = fopen( "/tmp/tpmdata.dat", "rb" );
	if( filePtr == NULL )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
	fseek( filePtr, 0, SEEK_END );
	dataSize = ftell( filePtr );
	fclose( filePtr );
	*appData = malloc( dataSize );
	if( *appData == NULL )
		return( TSS2_FAPI_RC_MEMORY );
	count = fread( *appData, dataSize, 1, filePtr );
	fclose( filePtr );
	*appDataSize = ( int ) dataSize;
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC pFapi_GetInfo( FAPI_CONTEXT *context, char **info )
	{
	*info = "Fake TPM driver";
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC pFapi_GetRandom( FAPI_CONTEXT *context, size_t numBytes, 
						 uint8_t **data )
	{
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC pFapi_GetTpmBlobs( FAPI_CONTEXT *context, char const *path, 
						   uint8_t **tpm2bPublic, size_t *tpm2bPublicSize, 
						   uint8_t **tpm2bPrivate, size_t *tpm2bPrivateSize, 
						   char **policy )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	static TPM2B_PUBLIC tpmPubkeyBlob;
	TPMT_PUBLIC *tpmtPubkey;
	TPMS_RSA_PARMS *rsaParams;
	TPM2B_PUBLIC_KEY_RSA *rsaPubKey;
	STREAM stream;
	MESSAGE_DATA msgData;
	BYTE integerValue[ CRYPT_MAX_PKCSIZE ];
	BYTE buffer[ 128 + CRYPT_MAX_PKCSIZE ];
	int integerLength, status;

	/* Get the RSA n value from the SPKI */
	setMessageData( &msgData, buffer, 128 + CRYPT_MAX_PKCSIZE );
	status = krnlSendMessage( rsaContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
	if( cryptStatusError( status ) )
		return( TSS2_RC_SUCCESS + 1 );
	sMemConnect( &stream, buffer, msgData.length );
	readSequence( &stream, NULL );
	readAlgoID( &stream, &cryptAlgo, ALGOID_CLASS_PKC );
	readBitStringHole( &stream, NULL, 128, DEFAULT_TAG );
	readSequence( &stream, NULL );
	status = readInteger( &stream, integerValue, CRYPT_MAX_PKCSIZE, 
						  &integerLength );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( TSS2_RC_SUCCESS + 1 );

	/* Set up the incredibly convoluted structure needed for the TPM API.  
	   The format of the RSA n value is never documented anywhere but 
	   Botan's BigInt() says that it takes a big-endian encoding and some 
	   Botan sample code passes the contents of raw rsaPubKey->buffer to it 
	   so we assume that it's big-endian */
	memset( &tpmPubkeyBlob, 0, sizeof( TPM2B_PUBLIC ) );
	tpmPubkeyBlob.size = sizeof( TPMT_PUBLIC );
	tpmtPubkey = &tpmPubkeyBlob.publicArea;
	tpmtPubkey->type = TPM2_ALG_RSASSA;
	rsaParams = &tpmtPubkey->parameters.rsaDetail;
	rsaParams->keyBits = 2048;
	rsaParams->exponent = 65537L;
	rsaPubKey = &tpmtPubkey->unique.rsa;
	memcpy( rsaPubKey->buffer, integerValue, integerLength );
	rsaPubKey->size = ( UINT16 ) integerLength;

	*tpm2bPublic = ( uint8_t * ) &tpmPubkeyBlob;
	*tpm2bPublicSize = sizeof( TPM2B_PUBLIC );

	return( TSS2_RC_SUCCESS );
	}

TSS2_RC pFapi_Initialize( FAPI_CONTEXT **context, char const *uri )
	{
	*context = ( FAPI_CONTEXT * ) "FAPI context memory";
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC pFapi_Provision( FAPI_CONTEXT *context, const char *authValueEh,
						 const char *authValueSh, 
						 const char *authValueLockout )
	{
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC pFapi_SetAppData( FAPI_CONTEXT *context, char const *path,
						  uint8_t const *appData, size_t appDataSize )
	{
	FILE *filePtr;

	filePtr = fopen( "/tmp/tpmdata.dat", "wb" );
	assert( filePtr != NULL );
	fwrite( appData, appDataSize, 1, filePtr );
	fclose( filePtr );
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC pFapi_Sign( FAPI_CONTEXT *context, char const *keyPath, 
					char const *padding, uint8_t const *digest, 
					size_t digestSize, uint8_t **signature, 
					size_t *signatureSize, char **publicKey, 
					char **certificate )
	{
	STREAM stream;
	static BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int payloadSize, i;

	sMemOpen( &stream, buffer, CRYPT_MAX_PKCSIZE );
	payloadSize = sizeofMessageDigest( CRYPT_ALGO_SHA2, digestSize );
	sputc( &stream, 0 );
	sputc( &stream, 1 );
	for( i = 0; i < bitsToBytes( 2048 ) - ( payloadSize + 3 ); i++ )
		sputc( &stream, 0xFF );
	sputc( &stream, 0 );
	writeMessageDigest( &stream, CRYPT_ALGO_SHA2, digest, digestSize );
	payloadSize = stell( &stream );
	sMemDisconnect( &stream );

	return( pFapi_Decrypt( context, keyPath, buffer, payloadSize,
						   signature, signatureSize ) );
	}
#endif /* USE_TPM_EMULATION */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a TPM-specific error to a cryptlib error */

CHECK_RETVAL
static int tpmMapError( const TSS2_RC tssResult, 
						IN_ERROR const int defaultError )
	{
	REQUIRES( cryptStatusError( defaultError ) );

	switch( tssResult )
		{
		case TSS2_RC_SUCCESS:
			return( CRYPT_OK );
		case TSS2_FAPI_RC_NO_DECRYPT_PARAM:
		case TSS2_FAPI_RC_NO_ENCRYPT_PARAM:
			return( CRYPT_ERROR_NOTAVAIL );
		case TSS2_FAPI_RC_MEMORY:
			return( CRYPT_ERROR_MEMORY );
		case TSS2_FAPI_RC_NOT_DELETABLE:
		case TSS2_FAPI_RC_AUTHORIZATION_FAILED:
			return( CRYPT_ERROR_PERMISSION );
		case TSS2_FAPI_RC_PATH_ALREADY_EXISTS:
			return( CRYPT_ERROR_DUPLICATE );
		case TSS2_BASE_RC_PATH_NOT_FOUND:
		case TSS2_FAPI_RC_PATH_NOT_FOUND:
			return( CRYPT_ERROR_NOTFOUND );
		case TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED:
			return( CRYPT_ERROR_SIGNATURE );
		case TSS2_FAPI_RC_NOT_PROVISIONED:
			return( CRYPT_ERROR_NOTINITED );
		case TSS2_FAPI_RC_ALREADY_PROVISIONED:
			return( CRYPT_ERROR_INITED );
		}

	return( defaultError );
	}

/* Get the device's FAPI_CONTEXT from an encryption context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getFapiContext( IN_PTR const CONTEXT_INFO *contextInfoPtr,
						   OUT_OPT_PTR FAPI_CONTEXT **fapiContexPtr )
	{
	CRYPT_DEVICE iCryptDevice;
	const DEVICE_INFO *deviceInfoPtr;
	FAPI_CONTEXT *fapiContext;
	int status;

	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( fapiContexPtr, sizeof( FAPI_CONTEXT * ) ) );

	/* Clear return value */
	*fapiContexPtr = NULL;

	/* Get the the device associated with this context */
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the TPM information from the device information */
	status = krnlAcquireObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( MESSAGE_PTR_CAST ) &deviceInfoPtr, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	fapiContext = ( FAPI_CONTEXT * ) deviceInfoPtr->contextHandle;
	krnlReleaseObject( iCryptDevice );
	ENSURES( fapiContext != NULL );

	*fapiContexPtr = fapiContext;

	return( CRYPT_OK );
	}

/* FAPI has no means of specifying things like algorithms, modes, or key
   sizes, there's just a generic mechanism hidden behind the magic catch-all
   "policy", meaning you specify a magic text string and hope that the TPM's 
   policy will support a profile that can do something with this.  
   
   The first element is the cryptoprofile or algorithm and sometimes key 
   size, we take a guess at the most likely to be recognised one.  
   
   The second element is the hiearchy, sometimes specified as Hx and 
   sometimes as H_x but the Hx form is more common.  We use HN for the 
   null hierarchy since it's neither endorsement, platform, or storage.

   The third element is the object ancestor.  As usual there are multiple
   incompatible definitions for how this is specified, for example the TPM
   docs mention things like snk = system non-duplicatable key, sdk = 
   system duplicatable key, etc, but the FAPI docs say it should be srk =
   system root key.

   Finally we have the vendor or application ID, specified as 
   <software>-<keyname>.  For now, and for lack of any other obvious
   option, we assume the keyname value will be a small integer that can
   be used to distinguish keys like an object handle would in a sane API.
   
   An alternative option, which takes advantage of the weird way that FAPI
   references keys and which would at least allow lookup by label, would be
   to turn the label into a part of the <keyname>

	HASH_FUNCTION_ATOMIC hashFunctionAtomic;

	getHashAtomicParameters( CRYPT_ALGO_SHA1, 0, &hashFunctionAtomic, NULL );
	hashFunctionAtomic( hashBuffer, CRYPT_MAX_HASHSIZE, label, labelLength );
	base64encode( keyID, 16, &keyIDlen, hashBuffer, 12, CRYPT_CERTTYPE_NONE );
	memcpy( string + algoStringLength, keyID, 16 );

   (with filtering of '+' and '/'), however this isn't necessary because 
   we're using the memory-mapped PKCS #15 keyset for indexing and lookup */

static int getAlgorithmString( IN_ALGO const CRYPT_ALGO_TYPE algorithm,
							   OUT_BUFFER( maxStringLength, \
										   *stringLength ) void *string,
							   IN_LENGTH_SHORT_MIN( 32 ) \
									const int maxStringLength, 
							   OUT_LENGTH_SHORT_Z int *stringLength )
	{
	const char *algoString;
	int algoStringLength;

	assert( isWritePtr( string, maxStringLength ) );
	assert( isWritePtr( stringLength, sizeof( int ) ) );

	REQUIRES( isEnumRange( algorithm, CRYPT_ALGO ) );
	REQUIRES( isShortIntegerRangeMin( maxStringLength, 32 ) );

	/* Clear return values */
	memset( string, 0, min( 16, maxStringLength ) );
	*stringLength = 0;

	/* Construct the required algorithm string.  For now we assume a single
	   private key, both because there's no way to tell how many are 
	   supported (see the long comment above) although it's likely to be a
	   very small number, and because there's no easy way to manage them via
	   labels since we need the label to create the key but there's no way
	   to know anything about the key until it's already been created */
	switch( algorithm )
		{
		case CRYPT_ALGO_RSA:
			/* RSA, default P_RSASHA256.  May also be P_RSASHA1, P_RSASHA2, 
			   and more specific stuff like P_RSA2048SHA1 and 
			   P_RSA2048SHA256, but mostly P_RSA seems to imply RSA-2048 */
			algoString = "/P_RSASHA256/HN/srk/cryptlib-00";
			break;

		case CRYPT_ALGO_ECDSA:
			/* ECDSA, default P_ECCP256.  May also be P_ECCP384, P_ECCP521 */
			algoString = "/P_ECCP256/HN/srk/cryptlib-00";
			break;

		default:
			retIntError();
		}
	algoStringLength = strlen( algoString );
	if( algoStringLength < 1 || algoStringLength + 1 > maxStringLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Copy the string across, including the null terminator */
	ENSURES( rangeCheck( algoStringLength + 1, 1, maxStringLength ) );
	memcpy( string, algoString, algoStringLength + 1 );
	*stringLength = algoStringLength + 1;

	return( CRYPT_OK );
	}

/* Because PKCS #11 splits PKC keys into two distinct objects we in theory 
   end up with one that can only perform private-key operations and one that 
   can only perform public-key operations.  This isn't a problem because 
   cryptlib always creates native objects for public-key operations since 
   they're much faster than device ones where the devices are typically 
   smart cards.  In theory we could enable public-key operations on the 
   private-key objects as well because they'd never get used as such, 
   however they will actually get used when performing a pairwise 
   consistency check after signing, which leads to problems because the 
   xxxVerify() functions return an internal error if called.  Because of 
   this we don't enable public-key operations for private-key objects even 
   if the device is theoretically capable of doing this */

static int updateActionFlags( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							  IN_BOOL const BOOLEAN isPrivateKey )
	{
	int actionFlags = 0;

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isConvAlgo( cryptAlgo ) || isPkcAlgo( cryptAlgo ) || \
			  isMacAlgo( cryptAlgo ) );
	REQUIRES( isBooleanValue( isPrivateKey ) );

	if( isConvAlgo( cryptAlgo ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
		}
	if( isPkcAlgo( cryptAlgo ) && isPrivateKey )
		{
		if( isCryptAlgo( cryptAlgo ) )
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
		if( isSigAlgo( cryptAlgo ) )
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
		if( cryptAlgo == CRYPT_ALGO_RSA )
			{
			/* Because of the weird way in which the TPM API ties RSA 
			   formatting to the key type used there's no way to perform 
			   general purpose RSA encryption or decryption, so we make the
			   context internal-only to ensure that it's only called from the
			   appropriate cryptlib functions */
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
			}
		if( isDlpAlgo( cryptAlgo ) || isEccAlgo( cryptAlgo ) )
			{
			/* Because of the special-case data formatting requirements for 
			   DLP/ECDLP algorithms we make the usage internal-only */
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
			}
		}
	if( isMacAlgo( cryptAlgo ) )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_ALL );

	return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, 
							 ( MESSAGE_CAST ) &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

/* Get random data from the device */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getRandomFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
							  OUT_BUFFER_FIXED( length ) void *data,
							  IN_LENGTH_SHORT const int length,
							  STDC_UNUSED INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	FAPI_CONTEXT *fapiContext = \
			( FAPI_CONTEXT * ) deviceInfoPtr->contextHandle;
	TSS2_RC tssResult;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtrDynamic( data, length ) );
	assert( messageExtInfo == NULL );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );
	REQUIRES( fapiContext != NULL );

	tssResult = pFapi_GetRandom( fapiContext, length, data );
	return( tpmMapError( tssResult, CRYPT_ERROR_FAILED ) );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Open and close a session with the TPM */

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	FAPI_CONTEXT *fapiContext = \
			( FAPI_CONTEXT * ) deviceInfoPtr->contextHandle;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	if( tpmInitialised )
		{
		REQUIRES_V( fapiContext != NULL );

		pFapi_Finalize( &fapiContext );
		tpmInitialised = FALSE;
		}
	deviceInfoPtr->contextHandle = NULL;
	CLEAR_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE | \
									  DEVICE_FLAG_LOGGEDIN );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
						 IN_BUFFER( nameLength ) const char *name,
						 IN_LENGTH_SHORT const int nameLength )
	{
	const DEV_STORAGE_FUNCTIONS *storageFunctions = \
					DATAPTR_GET( deviceInfoPtr->storageFunctions );
	TPM_INFO *tpmInfo = deviceInfoPtr->deviceTPM;
	FAPI_CONTEXT *fapiContext;
	MESSAGE_DATA msgData;
	BYTE buffer[ 32 + 8 ];
	TSS2_RC tssResult;
	const int quality = 95;
	char *fapiInfoString;
	int fapiInfoStringLength, status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( name == NULL && nameLength == 0 );
	REQUIRES( storageFunctions != NULL );

	/* Initialise the TPM FAPI library.  The URI parameter must be NULL 
	   (FAPI version 0.94 Section 4.1) */
	if( pFapi_Initialize( &fapiContext, NULL ) != TSS2_RC_SUCCESS )
		return( CRYPT_ERROR_OPEN );
	deviceInfoPtr->contextHandle = fapiContext;
	tpmInitialised = TRUE;

	/* Copy out the FAPI driver and device information so that the user can 
	   access it by name.  This also serves as a general-purpose 
	   everything-OK check */
	tssResult = pFapi_GetInfo( fapiContext, &fapiInfoString );
	if( tssResult != TSS2_RC_SUCCESS )
		{
		DEBUG_DIAG(( "Couldn't get FAPI info for '" TPM_LIBNAME "'" ));
		shutdownFunction( deviceInfoPtr );
		return( CRYPT_ERROR_OPEN );
		}
	DEBUG_DIAG(( "Initialised TPM FAPI driver '%s'", fapiInfoString ));
	fapiInfoStringLength = min( strlen( fapiInfoString ), CRYPT_MAX_TEXTSIZE );
	REQUIRES( rangeCheck( fapiInfoStringLength, 1, CRYPT_MAX_TEXTSIZE ) );
	memcpy( tpmInfo->labelBuffer, fapiInfoString, fapiInfoStringLength );
	sanitiseString( tpmInfo->labelBuffer, CRYPT_MAX_TEXTSIZE, 
					fapiInfoStringLength );
	deviceInfoPtr->label = tpmInfo->labelBuffer;
	deviceInfoPtr->labelLen = strlen( tpmInfo->labelBuffer );

	/* Grab 256 bits of entropy and send it to the system device.  Since 
	   we're using a crypto hardware device we assume that it's good-quality 
	   entropy */
	status = getRandomFunction( deviceInfoPtr, buffer, 32, NULL );
	ENSURES( cryptStatusOK( status ) );
	setMessageData( &msgData, buffer, 32 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_SETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_ENTROPY );
	if( cryptStatusOK( status ) )
		{
		( void ) krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_SETATTRIBUTE,
								  ( MESSAGE_CAST ) &quality,
								  CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
		}
	zeroise( buffer, 32 );

	/* Open the PKCS #15 storage object used to store metadata for the keys 
	   in the TPM */
	status = openDeviceStorageObject( &deviceInfoPtr->iCryptKeyset, 
									  CRYPT_KEYOPT_NONE,
									  deviceInfoPtr->objectHandle,
									  storageFunctions, 
									  deviceInfoPtr->contextHandle,
									  FALSE, DEVICE_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );

	/* The TPM is hardwired into the system and always present and ready for
	   use.  Technically we may not be logged in but since there's no way to
	   do this via FAPI we assume that the TPM has been activated 
	   externally */
	SET_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE | \
									DEVICE_FLAG_LOGGEDIN );

	return( CRYPT_OK );
	}

/* Handle device control functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int controlFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type,
							IN_BUFFER_OPT( dataLength ) void *data, 
							IN_LENGTH_SHORT_Z const int dataLength,
							STDC_UNUSED INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	TPM_INFO *tpmInfo = deviceInfoPtr->deviceTPM;
	FAPI_CONTEXT *fapiContext = \
			( FAPI_CONTEXT * ) deviceInfoPtr->contextHandle;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( isAttribute( type ) || isInternalAttribute( type ) );
	REQUIRES( fapiContext != NULL );

	/* Handle authorisation value changes.  These can only be set when the
	   TPM is initialised so all we an do at this point is record them for
	   the initialisation step */
	if( type == CRYPT_DEVINFO_SET_AUTHENT_USER )
		{
		REQUIRES( rangeCheck( dataLength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( tpmInfo->authValueEh, data, dataLength );
		tpmInfo->authValueEhLen = dataLength;

		return( CRYPT_OK );
		}
	if( type == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR )
		{
		REQUIRES( rangeCheck( dataLength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( tpmInfo->authValueLockout, data, dataLength );
		tpmInfo->authValueLockoutLen = dataLength;

		return( CRYPT_OK );
		}

	/* Handle initialisation and zeroisation */
	if( type == CRYPT_DEVINFO_INITIALISE || \
		type == CRYPT_DEVINFO_ZEROISE )
		{
		BYTE authValueEh[ CRYPT_MAX_TEXTSIZE + 1 + 8 ];
		BYTE authValueLockout[ CRYPT_MAX_TEXTSIZE + 1 + 8 ];
		TSS2_RC tssResult;

		/* Make sure that we've got the two authentication values that we 
		   need */
		if( tpmInfo->authValueEhLen <= 0 )
			{
			retExt( CRYPT_ERROR_NOTINITED,
					( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
					  "TPM initialisation needs privacy authentication "
					  "value to be set" ) );
			}
		if( tpmInfo->authValueLockoutLen <= 0 )
			{
			retExt( CRYPT_ERROR_NOTINITED,
					( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
					  "TPM initialisation needs lockout authentication "
					  "value to be set" ) );
			}

		/* Convert the authentication values to null-terminated strings and 
		   provision the TPM */
		REQUIRES( rangeCheck( tpmInfo->authValueEhLen, 
							  1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( authValueEh, tpmInfo->authValueEh, tpmInfo->authValueEhLen );
		authValueEh[ tpmInfo->authValueEhLen ] = '\0';
		REQUIRES( rangeCheck( tpmInfo->authValueLockoutLen, 
							  1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( authValueLockout, tpmInfo->authValueLockout, 
				tpmInfo->authValueLockoutLen );
		authValueLockout[ tpmInfo->authValueLockoutLen ] = '\0';
		tssResult = pFapi_Provision( fapiContext, authValueEh, NULL, 
									 authValueLockout );
		if( tssResult != TSS2_RC_SUCCESS )
			return( tpmMapError( tssResult, CRYPT_ERROR_FAILED ) );

		return( CRYPT_OK );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*						 	TPM Storage Support Routines					*
*																			*
****************************************************************************/

/* Get a reference to built-in storage for keys and certificates.  This has 
   a PKCS #15 keyset mapped over the top of it.  The storage is an in-memory 
   buffer that can be committed to backing store when the update-notify 
   function is called to indicate that the buffer contents have been 
   updated */

static BYTE storage[ TPM_BUFFER_SIZE + 8 ] = { 0 };
static BOOLEAN storageInitialised = FALSE;

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int loadStorage( IN_PTR void *contextHandle )
	{
	FAPI_CONTEXT *fapiContext = ( FAPI_CONTEXT * ) contextHandle;
	TSS2_RC tssResult;
	void *appDataPtr;
	size_t appDataSize;

	REQUIRES( contextHandle != NULL );
	REQUIRES( fapiContext != NULL );

	/* Try and read the data from backing store */
	tssResult = pFapi_GetAppData( fapiContext, FAPI_APPDATA_PATH,
								  ( uint8_t ** ) &appDataPtr, &appDataSize );
	if( tssResult != TSS2_RC_SUCCESS )
		{
		/* If there's no data present in the backing store, let the caller 
		   know */
		if( tssResult == TSS2_BASE_RC_PATH_NOT_FOUND || 
			tssResult == TSS2_FAPI_RC_PATH_NOT_FOUND )
			{
			memset( storage, 0, TPM_BUFFER_SIZE );
			storageInitialised = TRUE;
			return( OK_SPECIAL );
			}
		
		return( tpmMapError( tssResult, CRYPT_ERROR_OPEN ) );
		}
	if( appDataSize < 1 || appDataSize > TPM_BUFFER_SIZE )
		{
		pFapi_Free( appDataPtr );
		return( CRYPT_ERROR_OVERFLOW );
		}

	/* Copy the data into the local buffer and free the memory that 
	   Fapi_GetAppData() allocated on read */
	memset( storage, 0, TPM_BUFFER_SIZE );
	REQUIRES( rangeCheck( appDataSize, 1, TPM_BUFFER_SIZE ) );
	memcpy( storage, appDataPtr, appDataSize );
	pFapi_Free( appDataPtr );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int tpmGetStorage( IN_PTR void *contextHandle,
						  OUT_BUFFER_ALLOC_OPT( *storageSize ) \
								void **storageAddr,
						  OUT_LENGTH int *storageSize )
	{
	int status;

	assert( isWritePtr( storageAddr, sizeof( void * ) ) );
	assert( isWritePtr( storageSize, sizeof( int ) ) );

	REQUIRES( contextHandle != NULL );

	/* Clear return values */
	*storageAddr = NULL;
	*storageSize = 0;

	/* If the storage is already initialised, just return a reference to 
	   it */
	if( storageInitialised )
		{
		*storageAddr = storage;
		*storageSize = TPM_BUFFER_SIZE;

		return( CRYPT_OK );
		}

	/* Try and load the storage buffer from backing store */
	status = loadStorage( contextHandle );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		return( status );
	*storageAddr = storage;
	*storageSize = TPM_BUFFER_SIZE;

	return( status );	
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int tpmStorageUpdateNotify( IN_PTR void *contextHandle,
								   IN_LENGTH const int dataLength )
	{
	TSS2_RC tssResult;

	REQUIRES( contextHandle != NULL );
	REQUIRES( ( dataLength == CRYPT_UNUSED ) || \
			  isIntegerRange( dataLength ) );
	
	/* If the data in the in-memory buffer is no longer valid, for example 
	   due to a failed update attempt, re-fill the buffer with the original 
	   data from the backing store */
	if( dataLength == CRYPT_UNUSED )
		return( loadStorage( contextHandle ) );

	/* If the in-memory data is now empty, erase the backing store */
	if( dataLength == 0 )
		{
		tssResult = pFapi_Delete( contextHandle, FAPI_APPDATA_PATH );
		if( tssResult != TSS2_RC_SUCCESS )
			return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );
		memset( storage, 0, TPM_BUFFER_SIZE );
		storageInitialised = FALSE;

		return( CRYPT_OK );
		}

	/* Data from 0...dataLength has been updated, write it to backing store,
	   optionally erasing the remaining area.  cryptlib updates are atomic 
	   so the entire data block will be updated at once, there won't be any
	   random-access changes made to ranges within the data block */
	REQUIRES( rangeCheck( dataLength, 1, TPM_BUFFER_SIZE ) );
	memset( storage + dataLength, 0, TPM_BUFFER_SIZE - dataLength );
	tssResult = pFapi_SetAppData( contextHandle, FAPI_APPDATA_PATH, 
								  storage, dataLength );
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int tpmDeleteItem( IN_PTR_OPT void *contextHandle,
						  const int storageRef )
	{
	REQUIRES( contextHandle != NULL );
	REQUIRES( storageRef >= 0 && storageRef < 16 );

//	deletePersonality( storageRef );
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int tpmLookupItem( IN_BUFFER( storageIDlength ) \
								const void *storageID,
						  IN_LENGTH_SHORT const int storageIDlength,
						  OUT_INT_Z int *storageRef )
	{
	assert( isReadPtrDynamic( storageID, storageIDlength ) );
	assert( isWritePtr( storageRef, sizeof( int ) ) );

	REQUIRES( storageIDlength >= 4 && storageIDlength <= KEYID_SIZE );

	/* Clear return value */
	*storageRef = CRYPT_ERROR;

//	return( lookupPersonality( storageID, storageIDlength, storageRef ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

/* Perform a self-test */

CHECK_RETVAL \
static int selfTestFunction( void )
	{
	/* There's no easy way to perform a self-test, however it's probably 
	   done by the TPM on power-up so we assume that the test has 
	   succeeded */
	return( CRYPT_OK );
	}

/* Encrypt/decrypt / sig-check/sign a data block */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
							IN_LENGTH_SHORT int noBytes )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* This function is present but isn't used as part of any normal 
	   operation because cryptlib does the same thing much faster in 
	   software and because some tokens don't support public-key 
	   operations */
	DEBUG_DIAG(( "Warning: encryptFunction() called for device object, "
				 "should be handled via native object" ));

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int decryptFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
							IN_LENGTH_SHORT int noBytes )
	{
	FAPI_CONTEXT *fapiContext;
	BYTE algorithmString[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE *fapiData;
	TSS2_RC tssResult;
	BOOLEAN isSign = FALSE;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
	size_t fapiDataLength;
	int algorithmStringLen, hashSize DUMMY_INIT, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* Determine whether this is a sign or decrypt operation.  Normally this
	   wouldn't matter because we're fed pre-padded data and just perform the
	   RSA operation on it, however TPMs (or perhaps the TPM API) doesn't 
	   support raw RSA so we have to figure out what's being done by looking
	   at the data that we're fed, which is either PKCS #1 padded for signing
	   or random data for decryption */
	if( buffer[ 0 ] == 0x00 && buffer[ 1 ] == 0x01 && \
		buffer[ 2 ] == 0xFF && buffer[ 3 ] == 0xFF && \
		buffer[ 4 ] == 0xFF && buffer[ 5 ] == 0xFF )
		isSign = TRUE;

	/* If we're signing, undo the PKCS #1 padding to get the raw hash value */
	if( isSign )
		{
		CRYPT_ALGO_TYPE hashAlgo;
		STREAM stream;
		LOOP_INDEX i;

		/* The data begins 0x00 0x01 0xFF 0xFF, it's PKCS #1 signature 
		   padding, remove the padding */
		LOOP_MAX( i = 2, i < keySize, i++ )
			{
			ENSURES( LOOP_INVARIANT_MAX( i, 2, keySize - 1 ) );

			if( buffer[ i ] == 0 )
				break;
			}
		ENSURES( LOOP_BOUND_OK );
		i++;	/* Skip final 0 byte */

		/* Now we're at the encoded message digest, remove the encoding to 
		   get to the raw hash value */
		sMemConnect( &stream, buffer + i, noBytes - i );
		status = readMessageDigest( &stream, &hashAlgo, hashValue, 
									CRYPT_MAX_HASHSIZE, &hashSize );
		sMemDisconnect( &stream );
		ENSURES( cryptStatusOK( status ) );

		/* Since the TPM API hardcodes the hash algorithm into the path used
		   to access the key (see the comment in generateKeyFunction()), we 
		   can only use the hash algorithm that's hardcoded for the key, in 
		   this case SHA-256 */
		if( hashAlgo != CRYPT_ALGO_SHA2 || hashSize != bitsToBytes( 256 ) )
			{
			DEBUG_DIAG(( "Fapi_Sign() for RSA only accepts SHA-256 as the "
						 "hash algorithm." ));
			return( CRYPT_ERROR_NOTAVAIL );
			}
		}

	/* Get the FAPI context for the encryption context */
	status = getFapiContext( contextInfoPtr, &fapiContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the magic string used to identify the key type and location */
	status = getAlgorithmString( CRYPT_ALGO_RSA, algorithmString, 
								 CRYPT_MAX_TEXTSIZE, &algorithmStringLen );
	ENSURES( cryptStatusOK( status ) );

	/* Sign or decrypt the data as appropriate.  FAPI doesn't use user-
	   supplied buffers but allocates a new memory block each time, which
	   we have to copy back out to the caller */
	if( isSign )
		{
		tssResult = pFapi_Sign( fapiContext, algorithmString, "RSA_SSA",
								hashValue, hashSize, &fapiData, 
								&fapiDataLength, NULL, NULL );
		}
	else
		{
		tssResult = pFapi_Decrypt( fapiContext, algorithmString, buffer,
								   noBytes, &fapiData, &fapiDataLength );
		}
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	/* If we're decrypting, create dummy PKCS #1 padding around the 
	   recovered key */
	if( !isSign )
		{
		MESSAGE_DATA msgData;
		LOOP_INDEX i;
		int padSize = keySize - fapiDataLength;

		REQUIRES( isShortIntegerRangeNZ( padSize ) );

		/* Redo the PKCS #1 padding.  Note that this doesn't have to be 
		   cryptographically strong since it gets stripped as soon as we 
		   return to the caller, it just has to be random:

		  bufPtr							 keySize
			|									|
			+---+---+------------+---+----------+
			| 0 | 1 |   random   | 0 |   key    |
			+---+---+------------+---+----------+
					|			 |	 |			|
					<------------>	 <---------->
					 keySize -		  fapiDataLen
					 fapiDataLen - 3

		   This gets a bit ugly because the random padding has to be 
		   nonzero, which would require using the non-nonce RNG.  To work 
		   around this, we look for any zeroes in the data and fill them 
		   with some other value */
		buffer[ 0 ] = 0;
		buffer[ 1 ] = 2;
		setMessageData( &msgData, buffer + 2, padSize - 3 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		LOOP_EXT( i = 2, i < padSize - 1, i++, CRYPT_MAX_PKCSIZE + 1 )
			{
			ENSURES( LOOP_INVARIANT_EXT( i, 2, padSize - 2,
										 CRYPT_MAX_PKCSIZE + 1 ) );

			if( buffer[ i ] == 0 )
				{
				/* Create some sort of non-constant non-zero value to 
				   replace the zero byte with, since PKCS #1 can't have zero 
				   bytes.  Note again that this doesn't have to be a strong 
				   random value, it just has to vary a bit */
				const int pad = 0xAA ^ ( i & 0xFF );
				buffer[ i ] = pad ? intToByte( pad ) : 0x21;
				}
			}
		ENSURES( LOOP_BOUND_OK );
		buffer[ padSize - 1 ] = 0;
		ENSURES( 2 + ( padSize - 3 ) + 1 + fapiDataLength == keySize );
		REQUIRES( boundsCheck( padSize, fapiDataLength, noBytes ) );
		memcpy( buffer + padSize, fapiData, fapiDataLength );
		}
	else
		{
		/* We're signing, just copy the result to the caller */
		if( fapiDataLength > noBytes )
			status = CRYPT_ERROR_OVERFLOW;
		else
			{
			REQUIRES( rangeCheck( fapiDataLength, 1, noBytes ) );
			memcpy( buffer, fapiData, fapiDataLength );
			}
		}

	/* Clean up */
	zeroise( fapiData, fapiDataLength );
	pFapi_Free( fapiData );

	return( CRYPT_OK );
	}

/* Load a key.  This isn't possible with FAPI so we always return a not-
   available error */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initKeyFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							IN_BUFFER_OPT( keyLength ) const void *key,
							IN_LENGTH_SHORT_OPT const int keyLength )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( key == NULL && keyLength == 0 ) || \
			( isReadPtrDynamic( key, keyLength ) && \
			  keyLength == sizeof( CRYPT_PKCINFO_RSA ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( ( key == NULL && keyLength == 0 ) || \
			  ( key != NULL && keyLength == sizeof( CRYPT_PKCINFO_RSA ) ) );

	return( CRYPT_ERROR_NOTAVAIL );
	}

/* Generate a key.  The functionality provided by Fapi_CreateKey() is
   essentially unspecified, "The cryptographic profiles are configured in an
   implementation specific way" so there's no way to specify an algorithm,
   key size, or anything else apart from hardcoding it into the key path
   and hoping that the TPM driver supports it.
   
   Making things even crazier, the generated keys aren't referenced by
   something like a handle once created but by the absolute path used to
   create them, so the crypto object is instantiated each time that it's
   used.
   
   In addition since the path also encodes a bunch of other algorithm 
   details like, for example for public keys, the hash algorithm used with
   a signing key, it's not possible to use a signing key with two different
   hash algorithms because */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateKeyFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
								IN_LENGTH_SHORT_MIN( MIN_PKCSIZE * 8 ) \
									const int keySizeBits )
	{
	FAPI_CONTEXT *fapiContext;
	TPM2B_PUBLIC *tpmPubkeyBlob;
	TPMT_PUBLIC *tpmtPubkey;
	TPMS_RSA_PARMS *rsaParams;
	TPM2B_PUBLIC_KEY_RSA *rsaPubKey;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE eBuffer[ 8 + 8 ], *eValue;
	BYTE keyDataBuffer[ ( CRYPT_MAX_PKCSIZE * 2 ) + 8 ];
	BYTE algorithmString[ CRYPT_MAX_TEXTSIZE + 8 ];
	TSS2_RC tssResult;
	size_t tpmPubkeyBlobSize;
	int algorithmStringLen, keySize, eSize DUMMY_INIT;
	int keyDataSize DUMMY_INIT, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Get the FAPI context for the encryption context */
	status = getFapiContext( contextInfoPtr, &fapiContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the magic string used to identify the key type and location */
	status = getAlgorithmString( CRYPT_ALGO_RSA, algorithmString, 
								 CRYPT_MAX_TEXTSIZE, &algorithmStringLen );
	ENSURES( cryptStatusOK( status ) );

	/* Generate the key */
	tssResult = pFapi_CreateKey( fapiContext, algorithmString, 
								 "sign,decrypt", NULL, NULL );
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	/* Read back the public-key data and make sure that we got what we're
	   expecting.  It's pot luck what this will be, we can have any of
	   TPM_ALG_RSASSA = PKCS #1, TPM_ALG_RSAES = OAEP, or TPM_ALG_RSAPSS =
	   PSS, with both no control over what we're getting and the actual name 
	   being hidden behind random alphabet sssoup */
	tssResult = pFapi_GetTpmBlobs( fapiContext, algorithmString, 
								   ( uint8_t ** ) &tpmPubkeyBlob, 
								   &tpmPubkeyBlobSize, NULL, NULL, NULL );
	if( tssResult != TSS2_RC_SUCCESS )
		{
		( void ) pFapi_Delete( fapiContext, algorithmString );
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );
		}
	ENSURES( tpmPubkeyBlob->size == sizeof( TPMT_PUBLIC ) );
	tpmtPubkey = &tpmPubkeyBlob->publicArea;
	ENSURES( tpmtPubkey->type == TPM2_ALG_RSASSA );
	rsaParams = &tpmtPubkey->parameters.rsaDetail;
	rsaPubKey = &tpmtPubkey->unique.rsa;
	keySize = bitsToBytes( rsaParams->keyBits );

	/* Format the RSA e value, which is stored as an integer rather than a
	   bignum byte string, as a bignum byte string.  This requires writing
	   the value as an ASN.1 INTEGER and then skipping the tag and length
	   bytes at the start */
	sMemOpen( &stream, eBuffer, 8 );
	status = writeShortInteger( &stream, rsaParams->exponent, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		eSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		pFapi_Free( tpmPubkeyBlob );
		( void ) pFapi_Delete( fapiContext, algorithmString );
		return( status );
		}
	eSize -= 1 + 1;					/* Skip tag + length */
	eValue = eBuffer + 1 + 1;

	/* Send the public key data to the context.  We send the keying 
	   information as CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL rather than 
	   CRYPT_IATTRIBUTE_KEY_SPKI since the latter transitions the context 
	   into the high state.  We don't want to do this because we're already 
	   in the middle of processing a message that does this on completion, 
	   all that we're doing here is sending in encoded public key data for 
	   use by objects such as certificates */
	if( cryptStatusOK( status ) )
		{
		status = writeFlatPublicKey( keyDataBuffer, CRYPT_MAX_PKCSIZE * 2,
									 &keyDataSize, CRYPT_ALGO_RSA, 0,
									 rsaPubKey->buffer, rsaPubKey->size, 
									 eValue, eSize, NULL, 0, NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, keyDataBuffer, keyDataSize );
		status = krnlSendMessage( contextInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( contextInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE, &keySize, 
								  CRYPT_IATTRIBUTE_KEYSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = updateActionFlags( contextInfoPtr->objectHandle,
									CRYPT_ALGO_RSA, TRUE );
		}
	if( cryptStatusError( status ) )
		{
		pFapi_Free( tpmPubkeyBlob );
		( void ) pFapi_Delete( fapiContext, algorithmString );
		return( status );
		}

	/* Clean up */
	pFapi_Free( tpmPubkeyBlob );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Device Capability and Mechanism Routines				*
*																			*
****************************************************************************/

/* The capability information for the TPM, really just private-key ops.  
   There isn't any way to query a TPM for its capabilities (short of
   shelling out to tpm2_getcap and parsing the resulting JSON) so we just 
   have to assume that the default RSA with key size 2048 bits exists */

static const CAPABILITY_INFO capabilities[] = {
	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, bitsToBytes( 0 ), "RSA", 3,
		bitsToBytes( 2048 ), bitsToBytes( 2048 ), bitsToBytes( 2048 ),
		selfTestFunction, getDefaultInfo, NULL, NULL, initKeyFunction, generateKeyFunction, 
		encryptFunction, decryptFunction, NULL, NULL, NULL, NULL, NULL, NULL, 
		decryptFunction, encryptFunction, readPublicKeyRsaFunction, writePublicKeyRsaFunction },

	/* The end-of-list marker.  This value isn't linked into the 
	   capabilities list when we call initCapabilities() */
	{ CRYPT_ALGO_NONE }, { CRYPT_ALGO_NONE }
	};

/* Mechanisms supported by TPM devices.  These are actually cryptlib native 
   mechanisms layered on top of the TPM crypto, but not the full set 
   supported by the system device since TPMs really only support private-key
   ops.  The list is sorted in order of frequency of use in order to make 
   lookups a bit faster */

static const MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) importPKCS1 },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) signPKCS1 },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) sigcheckPKCS1 },
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }, { MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

static CAPABILITY_INFO_LIST capabilityInfoList[ 4 ];

/* Initialise the capability information */

static int initCapabilities( void )
	{
	int i;

	/* Build the list of available capabilities */
	memset( capabilityInfoList, 0, 
			sizeof( CAPABILITY_INFO_LIST ) * 4 );
	for( i = 0; capabilities[ i ].cryptAlgo != CRYPT_ALGO_NONE && \
				i < FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO ); i++ )
		{
		REQUIRES( sanityCheckCapability( &capabilities[ i ] ) );
		
		DATAPTR_SET( capabilityInfoList[ i ].info, 
					 ( CAPABILITY_INFO * ) &capabilities[ i ] );
		DATAPTR_SET( capabilityInfoList[ i ].next, NULL );
		if( i > 0 )
			{
			DATAPTR_SET( capabilityInfoList[ i - 1 ].next, 
						 &capabilityInfoList[ i ] );
			}
		}
	ENSURES( i < FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setDeviceTPM( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	static const DEV_STORAGE_FUNCTIONS storageFunctions = {
		tpmGetStorage, tpmStorageUpdateNotify, tpmDeleteItem, tpmLookupItem 
		};
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	/* Make sure that the TPM driver library is loaded */
	if( hTPM == NULL_INSTANCE )
		return( CRYPT_ERROR_OPEN );

	status = initCapabilities(); 
	REQUIRES( cryptStatusOK( status ) );

	FNPTR_SET( deviceInfoPtr->initFunction, initFunction );
	FNPTR_SET( deviceInfoPtr->shutdownFunction, shutdownFunction );
	FNPTR_SET( deviceInfoPtr->controlFunction, controlFunction );
	status = deviceInitStorage( deviceInfoPtr );
	ENSURES( cryptStatusOK( status ) );
	FNPTR_SET( deviceInfoPtr->getRandomFunction, getRandomFunction );
	DATAPTR_SET( deviceInfoPtr->capabilityInfoList, capabilityInfoList );
	DATAPTR_SET( deviceInfoPtr->mechanismFunctions, 
				 ( void * ) mechanismFunctions );
	deviceInfoPtr->mechanismFunctionCount = \
		FAILSAFE_ARRAYSIZE( mechanismFunctions, MECHANISM_FUNCTION_INFO );
	DATAPTR_SET( deviceInfoPtr->storageFunctions, 
				 ( void * ) &storageFunctions );

	return( CRYPT_OK );
	}
#endif /* USE_TPM */
