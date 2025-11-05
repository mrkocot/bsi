/****************************************************************************
*																			*
*					cryptlib TLS Extension Management						*
*					Copyright Peter Gutmann 1998-2021						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "tls.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/tls.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/* The maximum number of extensions that we allow before getting 
   suspicious */

#define MAX_EXTENSIONS		32

/* The maximum size for a single extension */

#define MAX_EXTENSION_SIZE	8192

/****************************************************************************
*																			*
*							TLS Extension Definitions						*
*																			*
****************************************************************************/

/* TLS extension information.  Further types are defined at
   http://www.iana.org/assignments/tls-extensiontype-values.

   We specify distinct minimum and maximum lengths for client- and server-
   side use (so minLengthClient is the minimum length that a client can 
   send).  A value of CRYPT_ERROR means that this extension isn't valid when 
   sent by the client or server */

typedef struct {
	const int type;					/* Extension type */
	const int minLengthClient, minLengthServer;	/* Min.length */
	const int maxLength;			/* Max.length */
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	const char *description;		/* Text description for error messages */
#endif /* USE_ERRMSGS || !NDEBUG */
	} EXT_CHECK_INFO;

#ifdef USE_ERRMSGS
  #define TYPENAME( text )		, text
#else
  #define TYPENAME( text )
#endif /* USE_ERRMSGS */

static const EXT_CHECK_INFO extCheckInfoTbl[] = {
	/* Server name indication (SNI), RFC 4366/RFC 6066:

		uint16		listLen
			byte	nameType
			uint16	nameLen
			byte[]	name */
	{ TLS_EXT_SNI, 1, 0, MAX_EXTENSION_SIZE 
	  TYPENAME( "server name indication" ) },

#ifndef CONFIG_CONSERVE_MEMORY
	/* Maximum fragment length, RFC 4366/RFC 6066:

		byte		fragmentLength */
	{ TLS_EXT_MAX_FRAGMENT_LENTH, 1, 1, 1 
	  TYPENAME( "fragment length" ) },

	/* Client certificate URL.  This dangerous extension allows a client to 
	   direct a server to grope around in arbitrary external (and untrusted) 
	   URLs trying to locate certificates, provinding a convenient mechanism 
	   for bounce attacks and all manner of similar firewall/trusted-host 
	   subversion problems:

		byte		chainType
		uint16		urlAndHashList
			uint16	urlLen
			byte[]	url
			byte	hashPresent
			byte[20] hash			-- If hashPresent flag set */
	{ TLS_EXT_CLIENT_CERTIFICATE_URL, 
	  1 + UINT16_SIZE + UINT16_SIZE + MIN_URL_SIZE + 1, CRYPT_ERROR, MAX_EXTENSION_SIZE
	  TYPENAME( "client certificate URL" ) },

	/* Trusted CA certificate(s), RFC 4366/RFC 6066.  This allows a client 
	   to specify which CA certificates it trusts and by extension which 
	   server certificates it trusts, supposedly to reduce handshake 
	   messages in constrained clients.  Since the server usually has only a 
	   single certificate signed by a single CA, specifying the CAs that the 
	   client trusts doesn't serve much purpose:

		uint16		caList
			byte	idType
			[ choice of keyHash, certHash, or DN, another 
			  ASN.1-as-TLS structure ] */
	{ TLS_EXT_TRUSTED_CA_KEYS, UINT16_SIZE + 1, CRYPT_ERROR, MAX_EXTENSION_SIZE 
	  TYPENAME( "trusted CA" ) },

	/* Truncate the HMAC to a nonstandard 80 bits rather than the de facto 
	   IPsec cargo-cult standard of 96 bits, RFC 3546/4366/6066.  
	   
	   In 2017, fourteen years after it was standardised, it was first 
	   noticed that none of the three publicly-available TLS implementations 
	   that support this could interoperate (they'd all implemented it 
	   differently), indicating that this capability has never actually been 
	   used by anyone, so we don't bother supporting it */
	{ TLS_EXT_TRUNCATED_HMAC, 0, 0, 0
	  TYPENAME( "truncated HMAC" ) },

	/* OCSP status request, RFC 4366/RFC 6066.  Another bounce-attack 
	   enabler, this time on both the server and an OCSP responder.  Both 
	   the responder list and the extensions list may have length zero:

		byte		statusType
		uint16		ocspResponderList	-- May be length 0
			uint16	responderLength
			byte[]	responder
		uint16	extensionLength			-- May be length 0
			byte[]	extensions */
	{ TLS_EXT_STATUS_REQUEST, 
	  1 + UINT16_SIZE + UINT16_SIZE, CRYPT_ERROR, MAX_EXTENSION_SIZE
	  TYPENAME( "OCSP status request" ) },

	/* User mapping.  Used with a complex RFC 4680 mechanism (the extension 
	   itself is in RFC 4681):

		byte		mappingLength
		byte[]		mapping */
	{ TLS_EXT_USER_MAPPING, 1 + 1, CRYPT_ERROR, 1 + 255
	  TYPENAME( "user-mapping" ) },

	/* Authorisation extenions.  From an experimental RFC for adding 
	   additional authorisation data to the TLS handshake, RFC 5878:

		byte		authzFormatsList
			byte	authzFormatType

	   with the additional authorisation data being carried in the 
	   SupplementalData handshake message */
	{ TLS_EXT_CLIENT_AUTHZ, 1 + 1, CRYPT_ERROR, 1 + 255
	  TYPENAME( "client-authz" ) },
	{ TLS_EXT_SERVER_AUTHZ, CRYPT_ERROR, 1 + 1, 1 + 255
	  TYPENAME( "server-authz" ) },

	/* OpenPGP key.  From an experimental (later informational) RFC with 
	   support for OpenPGP keys, RFC 5081/6091:

		byte		certTypeListLength
		byte[]		certTypeList */
	{ TLS_EXT_CERTTYPE, 1 + 1, CRYPT_ERROR, 1 + 255
	  TYPENAME( "cert-type (OpenPGP keying)" ) },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* Supported groups, formerly ECC curve IDs, RFC 4492 modified by RFC 
	   5246/TLS 1.2 and again by RFC 8446/TLS 1.3 where it was renamed:

		uint16		namedGroupListLength
		uint16[]	namedGroup */
	{ TLS_EXT_SUPPORTED_GROUPS, UINT16_SIZE + UINT16_SIZE, CRYPT_ERROR, 512
	  TYPENAME( "supported groups" ) },

	/* Supported ECC point formats, RFC 4492 modified by RFC 5246/TLS 1.2:

		byte		pointFormatListLength
		byte[]		pointFormat */
	{ TLS_EXT_EC_POINT_FORMATS, 1 + 1, 1 + 1, 255 
	  TYPENAME( "ECDH/ECDSA point format" ) },

#ifndef CONFIG_CONSERVE_MEMORY
	/* SRP user name, RFC 5054:

		byte		userNameLength
		byte[]		userName */
	{ TLS_EXT_SRP, 1 + 1, CRYPT_ERROR, 1 + 255 
	  TYPENAME( "SRP username" ) },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* Signature algorithms, RFC 5246/TLS 1.2:

		uint16		algorithmListLength
			byte	hashAlgo
			byte	sigAlgo */
	{ TLS_EXT_SIGNATURE_ALGORITHMS, UINT16_SIZE + 1 + 1, CRYPT_ERROR, 512 
	  TYPENAME( "signature algorithm" ) },

#ifndef CONFIG_CONSERVE_MEMORY
	/* DTLS for SRTP keying, RFC 5764:

		uint16		srtpProtectionProfileListLength
			uint16	srtpProtectionProfile
			byte[]	srtp_mki */
	{ TLS_EXT_USE_SRP, UINT16_SIZE + UINT16_SIZE + 1, CRYPT_ERROR, 512
	  TYPENAME( "DTLS SRTP keying" ) },

	/* DTLS heartbeat, RFC 6520:

		byte		heartBeatMode */
	{ TLS_EXT_HEARTBEAT, 1, 1, 1 
	  TYPENAME( "DTLS heartbeat" ) },

	/* TLS ALPN, RFC 7301:
		uint16		protocolNameListLength
			uint8	protocolNameLength
			byte[]	protocolName */
	{ TLS_EXT_ALPN, UINT16_SIZE + 1 + 1, CRYPT_ERROR, 512
	  TYPENAME( "ALPN" ) },

	/* OCSP status request v2, RFC 6961.  See the comment for 
	   TLS_EXT_STATUS_REQUEST:

		byte		statusType
		uint16		requestLength
			uint16	ocspResponderList	-- May be length 0
				uint16	responderLength
				byte[]	responder
			uint16	extensionLength		-- May be length 0
				byte[]	extensions */
	{ TLS_EXT_STATUS_REQUEST_V2, 
	  1 + UINT16_SIZE + UINT16_SIZE + UINT16_SIZE, CRYPT_ERROR, MAX_EXTENSION_SIZE 
	  TYPENAME( "OCSP status request v2" ) },

	/* Certificate transparency timestamp, RFC 6962.  This is another
	   Trusted-CA-certificate level of complexity extension, the client
	   sends an empty request and the server responds with an ASN.1-as-TLS
	   extension, a SignedCertificateTimestampList:

		uint16		signedCertTimestampListLength
			uint16	serialisedSignedCertTimestampLength
				byte[]	[ X.509 level of complexity ]

	   Decoding what all of this requires from the RFC is excessively
	   complex (the spec is vague and ambiguous in several locations, with
	   details of what's required scattered all over the RFC in a mixture of
	   ASN.1 and TLS notation), but requiring a length of 64 bytes seems
	   sound */
	{ TLS_EXT_CERT_TRANSPARENCY, 0, UINT16_SIZE + UINT16_SIZE + 64, MAX_EXTENSION_SIZE
	  TYPENAME( "certificate transparency" ) },

	/* Raw client/server public keys, RFC 7250:

		uint8		certificateTypeLength
			byte[]	certificateTypes */
	{ TLS_EXT_RAWKEY_CLIENT, 1 + 1, 1 + 1, 64
	  TYPENAME( "client raw public key" ) },
	{ TLS_EXT_RAWKEY_SERVER, 1 + 1, 1 + 1, 64
	  TYPENAME( "server raw public key" ) },

	/* Client hello padding, RFC 7685.  Used to work around buggy servers 
	   that can't handle client hellos of a certain size:

		uint16		paddingLength
			byte[]	padding */
	{ TLS_EXT_PADDING, UINT16_SIZE, CRYPT_ERROR, MAX_EXTENSION_SIZE
	  TYPENAME( "client hello padding" ) },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* Encrypt-then-MAC, RFC 7366 */
	{ TLS_EXT_ENCTHENMAC, 0, 0, 0
	  TYPENAME( "encrypt-then-MAC" ) },

	/* Extended Master Secret, RFC 7627 */
	{ TLS_EXT_EMS, 0, 0, 0
	  TYPENAME( "extended master secret" ) },

#ifndef CONFIG_CONSERVE_MEMORY
	/* Token binding, RFC 8472:

		byte		majorVersion
		byte		minorVersion
		byte		parameterLength
			byte[]	parameters */
	{ TLS_EXT_TOKENBIND, 1 + 1 + 1 + 1, 1 + 1 + 1 + 1, 128
	  TYPENAME( "token binding" ) },

	/* Cached information, RFC 7924.  Used by clients to notify the server 
	   that they already have information like the server's certificate 
	   chain, allowing the server to reduce the size of the handshake by
	   not sending it:

		uint16		cachedInfoLength
			byte[]	cachedInfo */
	{ TLS_EXT_CACHED_INFO, UINT16_SIZE + 1, UINT16_SIZE + 1, MAX_EXTENSION_SIZE
	  TYPENAME( "cached information" ) },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* TLS 1.2 LTS, RFC xxxx */
	{ TLS_EXT_TLS12LTS, 0, 0, 0
	  TYPENAME( "TLS 1.2 LTS" ) },

#ifndef CONFIG_CONSERVE_MEMORY
	/* Certificate compression, RFC 8879.  This allows the specification of a
	   compression algorithm to compress certificates, meaning an 
	   implementation has to integrate all of zlib et al in order to save 20
	   bytes in a mostly-uncompressible certificate:

		byte		compressionAlgoListLength
			byte	compressionAlgos */
	{ TLS_EXT_COMPRESS_CERT, 1 + 1, 1 + 1, 128
	  TYPENAME( "compress certificate" ) },

	/* Record size limit, RFC 8449.  Allows limiting the maximum record size 
	   to less than the default 16K, invented by people for whom the
	   TLS_EXT_MAX_FRAGMENT_LENTH extension that everything ignored wasn't
	   cromulent enough so they created a new one for everything to ignore.

		uint16		recordSizeLimit */
	{ TLS_EXT_RECORD_SIZE_LIMIT, UINT16_SIZE, UINT16_SIZE, UINT16_SIZE
	  TYPENAME( "record size limit" ) },

	/* Secure password exchange, RFC 8492.  A Dan Harkins special that tries
	   to push Dragonfly into TLS:

		byte	passwordName[] */
	{ TLS_EXT_PWD_PROTECT, 1, CRYPT_ERROR, 255
	  TYPENAME( "password with protected username" ) },
	{ TLS_EXT_PWD_CLEAR, 1, CRYPT_ERROR, 255
	  TYPENAME( "password with clear username" ) },
	{ TLS_EXT_PASSWORD_SALT, CRYPT_ERROR, 1, MAX_EXTENSION_SIZE
	  TYPENAME( "password salt" ) },

	/* Server identity pinning, RFC 8672.  Uses the server as a decryption 
	   oracle for a ticket held by the client in order to prove its 
	   identity, another ASN.1-as-TLS extension with lots of optional 
	   fields */
	{ TLS_EXT_TICKET_PINNING, 0, 4, MAX_EXTENSION_SIZE
	  TYPENAME( "ticket pinning" ) },

	/* Certificate-based authentication with external PSK, RFC 8773 */
	{ TLS_EXT_CERT_WITH_PSK, 0, 0, 0
	  TYPENAME( "certificate authentication with external PSK" ) },

	/* Delegated credentials draft.  A mechanism for allowing a server to 
	   issue its own credentials based on a CA-issued certificate without 
	   having to get a full certificate each time.  The contents are 
	   essentially a certificate but encoded in TLS format */
	{ TLS_EXT_DELEGATED_CREDENIALS, UINT16_SIZE + UINT16_SIZE, 32, MAX_EXTENSION_SIZE
	  TYPENAME( "delegated credentials" ) },

	/* Session ticket, RFC 4507/5077.  The client can send a zero-length 
	   session ticket to indicate that it supports the extension but doesn't 
	   have a session ticket yet, and the server can send a zero-length 
	   ticket to indicate that it'll send the client a new ticket later in 
	   the handshake.  Confusing this even more, the specification says that 
	   the client sends "a zero-length ticket" but the server sends "a 
	   zero-length extension".  The original specification, RFC 4507, was 
	   later updated by a second version, RFC 5077, that makes explicit (via 
	   Appendix A) the fact that there's no "ticket length" field in the 
	   extension, so that the entire extension consists of the opaque ticket 
	   data:

		byte[]		sessionTicket (implicit size) */
	{ TLS_EXT_SESSIONTICKET, 0, 0, MAX_EXTENSION_SIZE
	  TYPENAME( "session ticket" ) },

	/* Middlebox security protocol, ETSI TS 103 523-2.  A means of getting 
	   TLS through middleboxes */
	{ TLS_EXT_TLMSP, 5, 5, MAX_EXTENSION_SIZE
	  TYPENAME( "TLMSP" ) },
	{ TLS_EXT_TLMSP_PROXYING, 4, 4, 4
	  TYPENAME( "TLMSP proxying" ) },
	{ TLS_EXT_TLMSP_DELEGATE, 4 + 1 + 1, 4 + 1 + 1, MAX_EXTENSION_SIZE
	  TYPENAME( "TLMSP delegation" ) },

	/* DTLS-SRTP encrypted key transport, RFC 8870.  Used to distribute SRTP
	   keys to conference-call participants */
	{ TLS_EXT_SUPPORTED_EKT_CIPHERS, 1, 1, 255
	  TYPENAME( "DTLS-SRTP encrypted key transport" ) },

	/* Monster list of TLS 1.3 extensions:

	   Pre-shared key:
		complex[]	pskInfo				-- Client: Complex nested structure
		uint16		pskIdentity			-- Server

	   Early data:

	   Supported versions:
		byte		versionListLength	-- Client
			uint16[] versionList
		uint16		version				-- Server

	   Cookie:
		uint16		cookieLength
			byte[]	cookie

	   Key exchange modes:
		byte		keyexModesLength
			byte[]	keyexModes

	   Certificate authorities:
		uint16		caDNListLength
			byte[]	caDNList

	   OID filters:
		uint16		oidFilterListLength
			byte	oidLength
				byte[] oid
			uint16	extensionsLength	-- May be 0
				byte extensions

	   Post-handshake auth:

	   Certificate signature algorithms:
		uint16		algorithmListLength
			byte	hashAlgo
			byte	sigAlgo

	   Key share:
		uint16		keyShareListLength	-- Client, may be 0
			byte[]	keyShareList
		complex		keyShare			-- Server 

	  The description has a version designator without the string "TLS" 
	  since the code that prints it adds this before it prints the 
	  description */
	{ TLS_EXT_PRESHARED_KEY, 40, UINT16_SIZE, MAX_EXTENSION_SIZE
	  TYPENAME( "1.3 pre-shared key" ) },
	  /* If this is used then for no known reason it must be the last 
	     extension present (RFC 8446 section 4.2) */
	{ TLS_EXT_EARLY_DATA, 0, 0, 0
	  TYPENAME( "1.3 early data" ) },
#endif /* CONFIG_CONSERVE_MEMORY */

	{ TLS_EXT_SUPPORTED_VERSIONS, 1 + UINT16_SIZE, UINT16_SIZE, 64
	  TYPENAME( "1.3 supported versions" ) },

#ifndef CONFIG_CONSERVE_MEMORY
	{ TLS_EXT_COOKIE, UINT16_SIZE + 1, UINT16_SIZE + 1, MAX_EXTENSION_SIZE
	  TYPENAME( "1.3 cookie" ) },
	{ TLS_EXT_PSK_KEYEX_MODES, 1, CRYPT_ERROR, 128
	  TYPENAME( "1.3 key exchange modes" ) },
	{ TLS_EXT_CAS, UINT16_SIZE, UINT16_SIZE, MAX_EXTENSION_SIZE
	  TYPENAME( "1.3 certificate authorities" ) },
	{ TLS_EXT_OID_FILTERS, UINT16_SIZE + 1 + 1 + UINT16_SIZE, UINT16_SIZE + 1 + 1 + UINT16_SIZE, MAX_EXTENSION_SIZE
	  TYPENAME( "1.3 OID filters" ) },
	{ TLS_EXT_POST_HS_AUTH, 0, CRYPT_ERROR, 0
	  TYPENAME( "1.3 post-handshake auth" ) },
	{ TLS_EXT_SIG_ALGOS_CERT, UINT16_SIZE + 1 + 1, UINT16_SIZE + 1 + 1, 512
	  TYPENAME( "1.3 certificate signature algorithms" ) },
	{ TLS_EXT_KEY_SHARE, UINT16_SIZE, UINT16_SIZE + UINT16_SIZE + 32, MAX_EXTENSION_SIZE
	  TYPENAME( "1.3 key share" ) },
#endif /* CONFIG_CONSERVE_MEMORY */

#ifndef CONFIG_CONSERVE_MEMORY
	/* Certificate transparency information, RFC 6962.  The draft never 
	   actually manages to define what's in this extension apart from 
	   specifying that the client send an empty extension so we just set 
	   the limits to a generic 1...MAX */
	{ TLS_EXT_TRANSPARENCY_INFO, 0, 1, MAX_EXTENSION_SIZE
	  TYPENAME( "certificate transparency information" ) },

	/* Connection ID for DTLS, RFC 9146.  Used to select an SA for DTLS over 
	   source address or port changes:

		byte cid[] */
	{ TLS_EXT_CONNECTION_ID_OLD, 0, 0, 255
	  TYPENAME( "connection ID (deprecated)" ) },
	{ TLS_EXT_CONNECTION_ID, 0, 0, 255
	  TYPENAME( "connection ID" ) },

	/* DTLS-SRTP unknown-key-share-attack protection, RFC 8844:

		byte hash[] */
	{ TLS_EXT_EXTERNAL_ID_HASH, 0, 0, 32
	  TYPENAME( "DTLS-SRTP external ID hash" ) },
	{ TLS_EXT_EXTERNAL_SESSION_ID, 20, 20, 255
	  TYPENAME( "DTLS-SRTP external session ID" ) },

	/* DTLS for QUIC, RFC 9001.  An opaque blob defined as "whatever QUIC 
	   needs" */
	{ TLS_EXT_QUIC_PARAMETERS, 0, 0, MAX_EXTENSION_SIZE
	  TYPENAME( "DTLS for QUIC parameters" ) },

	/* TLS session ticket request, RFC 9149.  Contains a count of the number
	   of tickets requested (client) or sent (server) */
	{ TLS_EXT_TICKET_REQUEST, 1 + 1, 1, 1 + 1
	  TYPENAME( "ticket request" ) },

	/* DANE information, RFC 9102.  Used to communicate DANE information to
	   authenticate a server in place of or alongside the usual 
	   certificate */
	{ TLS_EXT_DNSSEC_CHAIN, UINT16_SIZE, UINT16_SIZE + 1, MAX_EXTENSION_SIZE
	  TYPENAME( "DNSSEC chain" ) },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* Secure renegotiation indication, RFC 5746:

		byte renegotiated_connection[]
	
	   See the comment below for why we (apparently) support this even 
	   though we don't do renegotiation.  We give the length as one, 
	   corresponding to zero-length content, the one is for the single-byte 
	   length field in the extension itself, set to a value of zero.  It can 
	   in theory be larger as part of the secure renegotiation process but 
	   this would be an indication of an attack since we don't do 
	   renegotiation */
	{ TLS_EXT_SECURE_RENEG, 1, 1, 1
	  TYPENAME( "secure renegotiation" ) },

	/* End-of-list marker */
	{ CRYPT_ERROR, 0, 0, 0 TYPENAME( NULL ) }, 
		{ CRYPT_ERROR, 0, 0, 0 TYPENAME( NULL ) }
	};

/* In addition to the variable-format extenions above we also support the 
   secure-renegotiation extension.  This is a strange extension to support 
   because cryptlib doesn't do renegotiation, but we have to send it at the 
   client side in order to avoid being attacked via a (non-cryptlib) server 
   that's vulnerable, and we have to process it on the server side in order 
   to not appear to be a vulnerable server (sigh) */

#define RENEG_EXT_SIZE	5
#define RENEG_EXT_DATA	"\xFF\x01\x00\x01\x00"

/****************************************************************************
*																			*
*							Read/Write Specific Extensions					*
*																			*
****************************************************************************/

/* SNI:

	uint16		listLen
		byte	nameType
		uint16	nameLen
		byte[]	name 

   If we're the client and we sent this extension to the server then the 
   server may responed with a zero-length server-name extension for no 
   immediately obvious purpose (if the server doesn't recognise the name 
   then it's required to send an 'unrecognised-name' alert so any non-alert 
   return means that the value was accepted, but for some reason it's 
   required to send a zero-length response anyway) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readSNI( INOUT_PTR STREAM *stream, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					IN_LENGTH_SHORT_Z const int extLength,
					IN_BOOL const BOOLEAN isServer )
	{
	BYTE nameBuffer[ MAX_DNS_SIZE + 8 ];
	int listLen, nameLen, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isShortIntegerRange( extLength ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* If we're the client then the server should have sent us an empty
	   extension */
	if( !isServer )
		return( ( extLength != 0 ) ? CRYPT_ERROR_BADDATA : CRYPT_OK );

	/* Remember that we've seen the server-name extension so that we can 
	   send a zero-length reply to the client */
	handshakeInfo->needSNIResponse = TRUE;

	/* Read the extension wrapper */
	status = listLen = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( listLen != extLength - UINT16_SIZE || \
		listLen < 1 + UINT16_SIZE || \
		listLen >= MAX_EXTENSION_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Read the name type and length */
	if( sgetc( stream ) != 0 )	/* Name type 0 = hostname */
		return( CRYPT_ERROR_BADDATA );
	status = nameLen = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( nameLen != listLen - ( 1 + UINT16_SIZE ) || \
		nameLen < MIN_DNS_SIZE || nameLen > MAX_DNS_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Read the SNI and hash it so that we can use it, alongside the 
	   sessionID, for scoreboard lookup */
	status = sread( stream, nameBuffer, nameLen );
	if( cryptStatusError( status ) )
		return( status );
	hashData( handshakeInfo->hashedSNI, KEYID_SIZE, nameBuffer, nameLen );
	handshakeInfo->hashedSNIpresent = TRUE;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeSNI( INOUT_PTR STREAM *stream,
					 INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *serverNamePtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME );
	URL_INFO urlInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( serverNamePtr != NULL );

	/* Extract the server FQDN from the overall server name value */
	status = sNetParseURL( &urlInfo, serverNamePtr->value, 
						   serverNamePtr->valueLength, URL_TYPE_HTTPS );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the server name */
	writeUint16( stream, 1 + UINT16_SIZE + urlInfo.hostLen );
	sputc( stream, 0 );		/* Type = DNS name */
	writeUint16( stream, urlInfo.hostLen );
	return( swrite( stream, urlInfo.host, urlInfo.hostLen ) );
	}

/* TLS 1.3 Supported Versions.  This is the actual supported version for TLS 
   1.3, which always claims to be TLS 1.2 in the proper TLS version fields:

	byte			listLen		-- Client only, server = single entry
		uint16[]	versions 

   This requires some complex juggling to fit what we allow in between 
   max( configured_min_version, explicitly_selected_min_version ) and 
   max_version */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readSupportedVersions( INOUT_PTR STREAM *stream,
								  INOUT_PTR SESSION_INFO *sessionInfoPtr,
								  IN_LENGTH_SHORT_Z const int extLength )
	{
	const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );
	int noVersionEntries = 1;	/* Server sends a single entry */
	int value, status;
	LOOP_INDEX i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isShortIntegerRange( extLength ) );
	REQUIRES( protocolInfo != NULL );

	/* The client sends a list of versions, the server sends a single 
	   version, so if we're the server we need to read the length field 
	   before the version information */
	if( isServer( sessionInfoPtr ) )
		{
		status = value = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( value != extLength - 1 || \
			value < UINT16_SIZE || value > ( UINT16_SIZE * 8 ) || \
			value % UINT16_SIZE != 0 )
			return( CRYPT_ERROR_BADDATA );
		noVersionEntries = value / UINT16_SIZE;
		}
	LOOP_SMALL( i = 0, i < noVersionEntries, i++ )
		{
		int version;

		ENSURES( LOOP_INVARIANT_SMALL( i, 0, noVersionEntries - 1 ) );
	
		/* Get the major version and minor version.  The major version is 
		   always TLS_MAJOR_VERSION, however as part of some misguided 
		   attempt to force "resiliency" Google Chrome will send random 
		   gibberish values to test whether the other side will accept 
		   random garbage in fixed-value fields.  To deal with this we
		   implement a Google braindamage detector which takes advantage of
		   the fact that the gibberish value is always the first field and
		   has the same invalid value in the high and low 8 bits */
		status = value = readUint16( stream );
		if( cryptStatusError( status ) )
			return( status );
		version = value >> 8;
		if( version != TLS_MAJOR_VERSION )
			{
			/* It's an invalid value, make sure that it's not just Google
			   braindamage */
			if( i == 0 && ( value >> 8 ) == ( value & 0xFF ) )
				{
				DEBUG_PRINT(( "  Google braindamage detected, skipping "
							  "gibberish TLS version value %d.%d (%X).\n", 
							  value >> 8, value & 0xFF, value ));
				continue;
				}
			return( CRYPT_ERROR_BADDATA );
			}

		/* Get the minor version, the value that we're interested in */
		version = value & 0xFF;
		if( version < TLS_MINOR_VERSION_SSL || \
			version > TLS_MINOR_VERSION_TLS13 + 2 )
			return( CRYPT_ERROR_BADDATA );
		
		/* If we're using TLS 1.3 and the peer has proposed it, switch the
		   version that we're using to that.  This overrides the version
		   negotiation in processVersionInfo(), which stops at TLS 1.2 even
		   for TLS 1.3 since this always pretends to be TLS 1.2 */
#ifdef USE_TLS13
		if( version != TLS_MINOR_VERSION_TLS13 || \
			protocolInfo->maxVersion < TLS_MINOR_VERSION_TLS13 )
			{
			/* It's not TLS 1.3 or we don't support TLS 1.3, continue */
			continue;
			}
		DEBUG_PRINT(( "%s offered TLS 1.3 in extension, switching to "
					  "TLS 1.3.\n", 
					  isServer( sessionInfoPtr ) ? "Client" : "Server" ));
		sessionInfoPtr->version = TLS_MINOR_VERSION_TLS13;
#endif /* USE_TLS13 */
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeSupportedVersions( INOUT_PTR STREAM *stream,
								   INOUT_PTR SESSION_INFO *sessionInfoPtr,
								   IN_RANGE( TLS_MINOR_VERSION_TLS, \
											 TLS_MINOR_VERSION_TLS13 ) \
										const int minVersion )
	{
	STREAM localStream;
	BYTE buffer[ 16 + 8 ];
	int endPos;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( minVersion >= TLS_MINOR_VERSION_TLS && \
			  minVersion <= TLS_MINOR_VERSION_TLS13 );

	/* Assemble the version information in a local buffer */
	sMemOpen( &localStream, buffer, 16 );
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		writeUint16( &localStream, ( TLS_MAJOR_VERSION << 8 ) | \
									 TLS_MINOR_VERSION_TLS13 );
		}
#endif /* USE_TLS13 */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		writeUint16( &localStream, ( TLS_MAJOR_VERSION << 8 ) | \
									 TLS_MINOR_VERSION_TLS12 );
		}
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS11 && \
		minVersion <= TLS_MINOR_VERSION_TLS11 )
		{
		writeUint16( &localStream, ( TLS_MAJOR_VERSION << 8 ) | \
									 TLS_MINOR_VERSION_TLS11 );
		}
	if( minVersion <= TLS_MINOR_VERSION_TLS )
		{
		writeUint16( &localStream, ( TLS_MAJOR_VERSION << 8 ) | \
									 TLS_MINOR_VERSION_TLS );
		}
	endPos = stell( &localStream );
	sMemDisconnect( &localStream );
	ENSURES( isShortIntegerRangeNZ( endPos ) );

	/* Write the assembled version information */
	sputc( stream, endPos );
	return( swrite( stream, buffer, endPos ) );
	}

/* Preferred (or at least supported) groups, formerly ECC named curves.  
   For the pre-TLS 1.3 case this is a somewhat problematic extension because 
   it applies to any use of ECC, so if (for some reason) the server wants to 
   use a P256 ECDH key with a P521 ECDSA signing key then it has to verify 
   that the client reports that it supports both P256 and P521.  Since our 
   limiting factor is the ECDSA key that we use for signing, we require that 
   the client report support for the curve that matches our signing key.  
   Support for the corresponding ECDH curve is automatic, since we support 
   all curves for ECDH that are supported for ECDSA.  However, we also have
   to make sure that the corresponding SHA-2 fashion statement is available,
   since we can't sign, for example, SHA2-256 with P521.

   This one-size-fits-all mess however also leads to a second problem and 
   that's if we're using a non-ECC server key.  In this case we have a 
   preferred curve for ECDH but not for ECDSA, leading to the following set 
   of possibilities:

	Keyex		  Private key

	ECDH		ECDSA		RSA			Result
	---			-----		---			------
	-			N/A			Yes		->	RSA
	OK			-			Yes		->	ECDH + RSA
	OK			Yes + OK	-		->	ECDH + ECDSA
	OK			Yes + OK	Yes		->	ECDH + ECDSA || ECDH + RSA

   What this means in terms of matching is that if a non-ECC server key is
   present then we match any curve that we support, if an ECC server key is
   present then we look for a match for the server key.

   For TLS 1.3, alongside changing the name from named curves to supported
   groups since it now includes DH values, the interpretation was changed so 
   that there's now a separate extension for signature algorithms so that 
   this applies purely to keyex groups.  However this isn't useful when 
   sending the thing as a client because we have no idea whether we'll be 
   talking TLS 1.3 or TLS not-1.3 at that point.
   
   In addition since the client encodes the keyex algorithm in the key_share
   extension that's stuffed into the client hello there's no point in 
   sending this extension because all it can do is duplicate the information 
   already present in the key_share extension, which is non-negotiable since 
   it's required for the keyex to work.  TLS 1.3 also requires (RFC 8446 
   section 4.2.8.0) that "Clients MUST NOT offer any KeyShareEntry values
   for groups not listed in the client's supported_groups extension", so we
   have to send this extension even though there's no point to it (the PSK
   extensions work similarly, clients have to send psk_key_exchange_modes
   in order to send a pre_shared_key extension).
   
   Because of all this we treat it as having the pre-1.3 semantics:

	uint16		supportedGroupListLength
	uint16[]	supportedGroup */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
static int readSupportedGroups( INOUT_PTR STREAM *stream, 
								INOUT_PTR SESSION_INFO *sessionInfoPtr, 
								IN_LENGTH_SHORT_Z const int extLength,
								OUT_ENUM_OPT( CRYPT_ECCCURVE ) \
									CRYPT_ECCCURVE_TYPE *preferredCurveIdPtr,
								OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
	static const MAP_TABLE curveIDTbl[] = {
		{ TLS_GROUP_SECP256R1, CRYPT_ECCCURVE_P256 },
#ifdef USE_SHA2_EXT
		{ TLS_GROUP_SECP384R1, CRYPT_ECCCURVE_P384 },
		{ TLS_GROUP_SECP521R1, CRYPT_ECCCURVE_P521 },
#endif /* USE_SHA2_EXT */
		{ TLS_GROUP_BRAINPOOLP256R1, CRYPT_ECCCURVE_BRAINPOOL_P256 },
#ifdef USE_SHA2_EXT
		{ TLS_GROUP_BRAINPOOLP384R1, CRYPT_ECCCURVE_BRAINPOOL_P384 },
		{ TLS_GROUP_BRAINPOOLP512R1, CRYPT_ECCCURVE_BRAINPOOL_P512 },
#endif /* USE_SHA2_EXT */
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	static const MAP_TABLE curveSizeTbl[] = {
		{ CRYPT_ECCCURVE_P256, bitsToBytes( 256 ) },
#ifdef USE_SHA2_EXT
		{ CRYPT_ECCCURVE_P384, bitsToBytes( 384 ) },
		{ CRYPT_ECCCURVE_P521, bitsToBytes( 521 ) },
#endif /* USE_SHA2_EXT */
		{ CRYPT_ECCCURVE_BRAINPOOL_P256, bitsToBytes( 256 ) },
#ifdef USE_SHA2_EXT
		{ CRYPT_ECCCURVE_BRAINPOOL_P384, bitsToBytes( 384 ) },
		{ CRYPT_ECCCURVE_BRAINPOOL_P512, bitsToBytes( 512 ) },
#endif /* USE_SHA2_EXT */
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	CRYPT_ECCCURVE_TYPE preferredCurveID = CRYPT_ECCCURVE_NONE;
	LOOP_INDEX i;
	int serverKeyAlgorithm DUMMY_INIT, serverKeySize DUMMY_INIT;
	int listLen, status;
#ifdef CONFIG_SUITEB_TESTS 
	int curvesSeen = 0;
#endif /* CONFIG_SUITEB_TESTS */

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( preferredCurveIdPtr, \
						sizeof( CRYPT_ECCCURVE_TYPE ) ) );

	REQUIRES( isShortIntegerRange( extLength ) );

	/* Clear return values */
	*preferredCurveIdPtr = CRYPT_ECCCURVE_NONE;
	*extErrorInfoSet = FALSE;

	/* Get the algorithm and size of the server's signing key */
	status = krnlSendMessage( sessionInfoPtr->privateKey,
							  IMESSAGE_GETATTRIBUTE, &serverKeyAlgorithm,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sessionInfoPtr->privateKey,
								  IMESSAGE_GETATTRIBUTE, &serverKeySize,
								  CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read and check the supported groups list header */
	status = listLen = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( listLen != extLength - UINT16_SIZE || \
		listLen < UINT16_SIZE || listLen > 64 || \
		( listLen % UINT16_SIZE ) != 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Read the list of supported groups, recording the most preferred 
	   one */
	LOOP_EXT( i = 0, i < listLen / UINT16_SIZE, i++, 64 + 1 )
		{
		int value, curveID, curveSize;

		ENSURES( LOOP_INVARIANT_EXT( i, 0, ( listLen / UINT16_SIZE ) - 1, 
									 64 + 1 ) );

		status = value = readUint16( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( !isEnumRange( value, TLS_GROUP ) )
			continue;	/* Unrecognised curve type */
		status = mapValue( value, &curveID, curveIDTbl, 
						   FAILSAFE_ARRAYSIZE( curveIDTbl, MAP_TABLE ) );
		if( cryptStatusError( status ) )
			continue;	/* Unrecognised curve type */
		status = mapValue( curveID, &curveSize, curveSizeTbl, 
						   FAILSAFE_ARRAYSIZE( curveSizeTbl, MAP_TABLE ) );
		ENSURES( cryptStatusOK( status ) );
#ifdef CONFIG_SUITEB
		if( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
			{
			const int suiteBinfo = \
						sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB;

			/* Suite B only allows P256 and P384.  At the 128-bit level both 
			   P256 and P384 are allowed, at the 256-bit level only P384 is 
			   allowed */
			if( curveID != CRYPT_ECCCURVE_P256 && \
				curveID != CRYPT_ECCCURVE_P384 )
				continue;
			if( suiteBinfo == TLS_PFLAG_SUITEB_256 && \
				curveID == CRYPT_ECCCURVE_P256 )
				continue;
  #ifdef CONFIG_SUITEB_TESTS 
			if( suiteBTestValue == SUITEB_TEST_BOTHCURVES )
				{
				/* We're checking whether the client sends both curve IDs, 
				   remember which ones we've seen so far */
				if( curveID == CRYPT_ECCCURVE_P256 )
					curvesSeen |= 1;
				if( curveID == CRYPT_ECCCURVE_P384 )
					curvesSeen |= 2;
				}
  #endif /* CONFIG_SUITEB_TESTS */
			}
#endif /* CONFIG_SUITEB */

		/* If we're using an ECC server key, make sure that the requested 
		   curve matches the key.  If not then all that we care about is 
		   whether ECC keyex is available, which is controlled by the 
		   curveID table so as long as we get to this point the curve is
		   supported */
		if( isEccAlgo( serverKeyAlgorithm ) && curveSize != serverKeySize )
			continue;

		/* We've got a matching curve and there's not already a better curve 
		   selected, remember it.  Note that this will select the client's
		   preferred curve rather than our one, so if the client proposes 
		   P521 before they propose P256 then that's what'll get selected
		   rather than the universal-standard P256.
		   
		   In theory we could exit at this point but we continue anyway to 
		   clear the remainder of the data */
		if( preferredCurveID == CRYPT_ECCCURVE_NONE )
			preferredCurveID = curveID;
		}
	ENSURES( LOOP_BOUND_OK );
#ifdef CONFIG_SUITEB_TESTS 
	/* If we're checking for the presence of both P256 and P384 as supported 
	   elliptic curves and we don't see them, complain */
	if( suiteBTestValue == SUITEB_TEST_BOTHCURVES && curvesSeen != 3 )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Supported elliptic curves extension should have "
				  "contained both P256 and P384 but didn't" ) );
		}
#endif /* CONFIG_SUITEB_TESTS */

	*preferredCurveIdPtr = preferredCurveID;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeSupportedGroups( INOUT_PTR STREAM *stream,
								 INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	static const int eccCurveInfo[] = {
		TLS_GROUP_FFDHE2048,		/* 2048-bit DH */
		TLS_GROUP_FFDHE3072,		/* 3096-bit DH */
	 /* TLS_GROUP_FFDHE4096,		// Pointlessly large group */
		TLS_GROUP_SECP256R1,		/* CRYPT_ECCCURVE_P256 */
		TLS_GROUP_BRAINPOOLP256R1,	/* CRYPT_ECCCURVE_BRAINPOOL_P256 */
#ifdef USE_SHA2_EXT
		TLS_GROUP_SECP384R1,		/* CRYPT_ECCCURVE_P384 */
		TLS_GROUP_SECP521R1,		/* CRYPT_ECCCURVE_P521 */
		TLS_GROUP_BRAINPOOLP384R1,	/* CRYPT_ECCCURVE_BRAINPOOL_P384 */
		TLS_GROUP_BRAINPOOLP512R1,	/* CRYPT_ECCCURVE_BRAINPOOL_P512 */
#endif /* USE_SHA2_EXT */
			TLS_GROUP_NONE, TLS_GROUP_NONE 
		};
	LOOP_INDEX i;
	const int curveListLen = 8;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

#ifdef CONFIG_SUITEB
	if( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
		{
		static const BYTE eccCurveSuiteB128Info[] = {
			TLS_GROUP_SECP256R1, 
			TLS_GROUP_SECP384R1, 
				TLS_GROUP_NONE, TLS_GROUP_NONE 
			};
		static const BYTE eccCurveSuiteB256Info[] = {
			0, TLS_GROUP_SECP384R1, 0, 0 
			};
		const int suiteBinfo = \
				sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB;

		if( suiteBinfo == TLS_PFLAG_SUITEB_128 )
			{
			eccCurveInfoPtr = eccCurveSuiteB128Info;
			eccCurveInfoLen = 2;
			}
		else				
			{
			eccCurveInfoPtr = eccCurveSuiteB256Info;
			eccCurveInfoLen = 1;
			}
  #ifdef CONFIG_SUITEB_TESTS 
		/* In some cases for test purposes we have to send invalid ECC
		   information */
		if( suiteBTestValue == SUITEB_TEST_CLIINVALIDCURVE )
			{
			static const BYTE eccCurveSuiteBInvalidInfo[] = {
				0, TLS_GROUP_SECP521R1, 
				0, TLS_GROUP_SECP192R1, 
				0, 0 
				};

			eccCurveInfoPtr = eccCurveSuiteBInvalidInfo;
			eccCurveInfoLen = 2;
			}
  #endif /* CONFIG_SUITEB_TESTS  */
		}
#endif /* CONFIG_SUITEB */

	status = writeUint16( stream, curveListLen * UINT16_SIZE );
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( eccCurveInfo, int ) && \
				  eccCurveInfo[ i ] != TLS_GROUP_NONE ,
			  i++ )
		{
		status = writeUint16( stream, eccCurveInfo[ i ] );
		}
	ENSURES( LOOP_BOUND_OK );

	return( status );
	}

/* Signature and hash algorithms, a combinatorial explosion of { hash, sig } 
   algorithm pairs (they're called SignatureAndHashAlgorithm in the spec but 
   are actually encoded as HashAndSignatureAlgorithm).  This is used both 
   for extensions and for the TLS 1.2 / 1.3 signature format.

   The background for the chaos described below is that TLS 1.2 and even 
   more so TLS 1.3 started the move from a straighforward cipher-suite 
   system with a few cipher suites that everyone used and many more that 
   everyone ignored, which told you exactly what you were getting at every 
   point in the process, to an IPsec-style a la carte mess where every 
   single thing was variable and negotiable.  TLS 1.3 made it even worse 
   with its 1RTT design, which means there's no way to actually negotiate 
   anything in advance because you've only got one message each way to get 
   things done, thus the need to either guess which options the other side 
   is using, run several crypto operations in parallel and then keep the 
   one the other side commits to, or just deal with the general mess that 
   this comment is about by using universal defaults like SHA-256 as much as 
   possible.

   Initially this complex and confusing extension was added in TLS 1.2 with 
   weird requirements attached to it, for example if the client indicates 
   hash algorithm X then the server (RFC 5246 section 7.4.2) has to somehow 
   produce a certificate chain signed only using that hash algorithm, as if 
   a particular algorithm choice for TLS use could somehow dictate what 
   algorithms the CA and certificate-processing library that's being used 
   will provide (in addition the spec is rather confused on this issue, 
   giving it first as a MUST and then a paragraph later as a SHOULD).  
   
   This also made some certificate signature algorithms like RSA-PSS 
   impossible even if the hash algorithm used is supported by both the TLS 
   and certificate library, because TLS before 1.3 only allowed the 
   specification of PKCS #1 v1.5 signatures.  
   
   What's worse, it creates a situation from which there's no recovery 
   because in the case of a problem all that the server can say is "failed", 
   but not "try again using this algorithm", while returning certificates or 
   a signature with the server's available algorithm (ignoring the 
   requirement to summarily abort the handshake in the case of a mismatch) 
   at least tells the client what the problem is.

   To avoid this mess we assume that everyone can do SHA-256, the TLS 1.2 
   default.  A poll of TLS implementers in early 2011 indicated that 
   everyone else ignores this requirement as well (one implementer described
   the requirement as "that is not just shooting yourself in the foot, that 
   is shooting 'the whole nine yards' (the entire ammunition belt) in your 
   foot"), so we're pretty safe here.

   Writing it is just as bad because we both have to emit the values in
   preferred-algorithm order and some combinations aren't available, so 
   instead of simply iterating down two lists we have to exhaustively
   enumerate each possible algorithm combination.

   The whole thing was made even messier in terms of encoding the values by 
   the TLS 1.3 UI refresh, which despite the claim that "values have been 
   allocated to align with TLS 1.2's encoding" (section 4.2.3) actually 
   encodes the values in what looks like reverse order to TLS 1.2, with the 
   signature type first and the hash second (rsa_pss_rsae_xxx), or with new 
   values invented for where the hash seems to be (rsa_pss_pss_xxx) due to 
   having to encode RSA-PSS twice, once when the certificate it's used with 
   contains the OID rsaEncryption (TLS_SIGHASHALGO_RSAPSSoid1_XXX) and a 
   second time when it contains the OID RSASSA-PSS 
   (TLS_SIGHASHALGO_RSAPSSoid2_XXX) .  To deal with this mess we build the 
   TLS 1.2 values from their component algorithm identifiers with 
   MK_SIGHASHID() while using predefined magic values for the TLS 1.3 values.

   But wait, there's more!  Although the client (usually) sends this 
   extension in its hello, the server doesn't send it so the client has no 
   way to know which signature algorithm to expect until it's already 
   processing the signature.  This means that in order to process the 
   signature we first need to process the signature before we can process
   the signature.  To get around this catch-22, we indicate that we only
   support the universal-standard SHA-256, the same as the hash that's
   used in the overall cipher suites.

   Another reason to assume SHA-256 is that in TLS 1.3 in yet another
   arbitrary requirement the server is required to abort the handshake if 
   the client doesn't send this extension (RFC 8446 section 4.2.3) but,
   for the same reason that we assume the universal default of SHA-256 for
   signatures above, we can just default to SHA-256 if we're the server and 
   don't get sent the extension and everything will keep working.

   TLS 1.3 requires (RFC 8446 section 4.2.3 and again in 4.4.3) that even if 
   PKCS #1 v1.5 signing is indicated in this extension, this only applies to 
   signatures in certificates even if the PKCS #1 v1.5 indication is present 
   in the signature_algorithms rather than signature_algorithm_certificates 
   extension.  Message signing, e.g. for cert_verify, has to make the 
   RSA-PSS fashion statement.

   Speaking of RSA-PSS, TLS 1.3 may or may not require (RFC 8446 section 
   4.2.3, which type of signature is being referred to is ambiguous) that
   the PSS parameters in the certificate be used in the signature.  
   Specifically, the text says "If the corresponding public key's parameters 
   are present, then the parameters in the signature MUST be identical to 
   those in the public key" which means either TLS is telling CAs how to
   create their certificates or it's requiring that an implementation dig
   down into certificates to extract low-level PSS parameters for use in
   signing.  For sanity's sake we ignore this requirement.

   Again with RSA-PSS, TLS 1.3 requires (RFC 8446 section 4.2.3) that a TLS 
   1.2 implementation accept an RSA-PSS signature if the client advertises
   this for TLS 1.3 purposes even though TLS 1.2 doesn't do RSA-PSS
   signatures (RFC 5246 section 7.4.2).

   We disallow SHA1 (except for DSA where it's needed due to the hardcoding
   into the signature format) since the whole point of TLS 1.2 was to move 
   away from it, and a poll on the ietf-tls list indicated that all known 
   implementations (all two of them at the time the poll was carried out) 
   work fine with this configuration.

   This extension should really be called dogs_breakfast, not 
   signature_algorithms.  In particular this one is an implicit dog's
   breakfast, while pre_shared_key is an explicit dog's breakfast:

	uint16		algorithmListLength
		byte	hashAlgo
		byte	sigAlgo */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
static int readSignatureAlgos( INOUT_PTR STREAM *stream, 
							   INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							   IN_LENGTH_SHORT_Z const int extLength,
							   OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
#ifdef CONFIG_SUITEB
	static const MAP_TABLE curveSizeTbl[] = {
		{ bitsToBytes( 256 ), TLS_HASHALGO_SHA2 },
		{ bitsToBytes( 384 ), TLS_HASHALGO_SHA384 },
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	const int suiteBinfo = sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB;
	int keySize, hashType, LOOP_ITERATOR;
  #ifdef CONFIG_SUITEB_TESTS 
	int hashesSeen = 0;
  #endif /* CONFIG_SUITEB_TESTS */
#endif /* CONFIG_SUITEB */
	int listLen, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isShortIntegerRange( extLength ) );

	/* Clear return values */
	*extErrorInfoSet = FALSE;

	/* Read and check the signature algorithm list header */
	status = listLen = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( listLen != extLength - UINT16_SIZE || \
		listLen < 1 + 1 || listLen > 64 + 64 || \
		( listLen % UINT16_SIZE ) != 0 )
		return( CRYPT_ERROR_BADDATA );

	/* If we're not using TLS 1.2+, skip the extension */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		return( sSkip( stream, listLen, MAX_INTLENGTH_SHORT ) );

	/* For the more strict handling requirements in Suite B only 256- or 
	   384-bit algorithms are allowed at the 128-bit level and only 384-bit 
	   algorithms are allowed at the 256-bit level */
#ifdef CONFIG_SUITEB
	/* If we're not running in Suite B mode then there are no additional
	   checks required */
	if( !suiteBinfo )
		{
		handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;

		return( sSkip( stream, listLen, MAX_INTLENGTH_SHORT ) );
		}

	/* Get the size of the server's signing key to try and match the 
	   client's preferred hash size */
	status = krnlSendMessage( sessionInfoPtr->privateKey, 
							  IMESSAGE_GETATTRIBUTE, &keySize,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );
	status = mapValue( keySize, &hashType, curveSizeTbl, 
					   FAILSAFE_ARRAYSIZE( curveSizeTbl, MAP_TABLE ) );
	if( cryptStatusError( status ) )
		{
		/* Suite B only allows P256 and P384 keys (checked by the higher-
		   level code when we add the server key) so we should never get to 
		   this situation */
		return( status );
		}
	handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_NONE;

	/* Read the hash and signature algorithms and choose the best one to 
	   use */
	LOOP_EXT_REV_CHECKINC( listLen > 0, listLen -= 1 + 1, 64 + 1 )
		{
		int hashAlgo, sigAlgo;

		ENSURES( LOOP_INVARIANT_EXT_REV_XXX( listLen, 1, MAX_INTLENGTH_SHORT, 
											 64 + 1 ) );

		/* Read the hash and signature algorithm and make sure that it's one 
		   that we can use.  At the 128-bit level both SHA256 and SHA384 are 
		   allowed, at the 256-bit level only SHA384 is allowed */
		hashAlgo = sgetc( stream );			/* Hash algorithm */
		status = sigAlgo = sgetc( stream );	/* Sig.algorithm */
		if( cryptStatusError( status ) )
			return( status );
		if( sigAlgo != TLS_SIGALGO_ECDSA || \
			( hashAlgo != TLS_HASHALGO_SHA2 && \
			  hashAlgo != TLS_HASHALGO_SHA384 ) )
			continue;
		if( suiteBinfo == TLS_PFLAG_SUITEB_256 && \
			hashAlgo != TLS_HASHALGO_SHA384 )
			continue;
  #ifdef CONFIG_SUITEB_TESTS 
		if( suiteBTestValue == SUITEB_TEST_BOTHSIGALGOS )
			{
			/* We're checking whether the client sends both hash algorithm 
			   IDs, remember which ones we've seen so far */
			if( hashAlgo == TLS_HASHALGO_SHA2 )
				hashesSeen |= 1;
			if( hashAlgo == TLS_HASHALGO_SHA384 )
				hashesSeen |= 2;
			}
  #endif /* CONFIG_SUITEB_TESTS */

		/* In addition to the general validity checks, the hash type also has
		   to match the server's key size */
		if( hashType != hashAlgo )
			continue;

		/* We've found one that we can use, set the appropriate variant.  
		   Note that since SHA384 is just a variant of SHA2, we always 
		   choose this if it's available.  Even if the order given is 
		   { SHA384, SHA256 } the parameter value for the original SHA384 
		   will remain set when SHA256 is subsequently read */
		handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;
		if( hashAlgo == TLS_HASHALGO_SHA384 )
			handshakeInfo->keyexSigHashAlgoParam = bitsToBytes( 384 );
		}
	ENSURES( LOOP_BOUND_EXT_REV_OK( 64 + 1 ) );

	/* For Suite B the client must send either SHA256 or SHA384 as an 
	   option */
	if( handshakeInfo->keyexSigHashAlgo == CRYPT_ALGO_NONE )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Signature algorithms extension should have "
				  "contained %sP384/SHA384 but didn't",
				  ( suiteBinfo != TLS_PFLAG_SUITEB_256 ) ? \
					"P256/SHA256 and/or " : "" ) );
		}
#ifdef CONFIG_SUITEB_TESTS 
	/* If we're checking for the presence of both SHA256 and SHA384 as 
	   supported hash algorithms and we don't see them, complain */
	if( suiteBTestValue == SUITEB_TEST_BOTHSIGALGOS && hashesSeen != 3 )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Signature algortithms extension should have contained "
				  "both P256/SHA256 and P384/SHA384 but didn't" ) );
		}
#endif /* CONFIG_SUITEB_TESTS */

	return( CRYPT_OK );
#else
	handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;

	return( sSkip( stream, listLen, MAX_INTLENGTH_SHORT ) );
#endif /* CONFIG_SUITEB */
	}

#define MK_SIGHASHID( sig, hash )	( ( hash << 8 ) | sig )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeSignatureAlgos( STREAM *stream )
	{
	typedef struct {
		CRYPT_ALGO_TYPE sigAlgo, hashAlgo;
		int tlsSigHashID;
		} SIG_HASH_INFO;
	static const SIG_HASH_INFO algoTbl[] = {
		/* RSA */
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHAng, 
		  MK_SIGHASHID( TLS_SIGALGO_RSA, 255 ) },
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  MK_SIGHASHID( TLS_SIGALGO_RSA, TLS_HASHALGO_SHA2 ) },
  #if defined( USE_SHA2_EXT ) && 0	/* See long comment at top */
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  MK_SIGHASHID( TLS_SIGALGO_RSA, TLS_HASHALGO_SHA384 ) },
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  MK_SIGHASHID( TLS_SIGALGO_RSA, TLS_HASHALGO_SHA512 ) },
  #endif /* USE_SHA2_EXT */
#ifdef USE_PSS
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGHASHALGO_RSAPSSoid1_SHA2 },
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGHASHALGO_RSAPSSoid2_SHA2 },
  #if defined( USE_SHA2_EXT ) && 0	/* See long comment at top */
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGHASHALGO_RSAPSSoid1_SHA384 },
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGHASHALGO_RSAPSSoid2_SHA384 },
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGHASHALGO_RSAPSSoid1_SHA512 },
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGHASHALGO_RSAPSSoid2_SHA512 },
  #endif /* USE_SHA2_EXT */
#endif /* USE_PSS */
		/* DSA */
#ifdef USE_DSA
		{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHAng, 
		  MK_SIGHASHID( TLS_SIGALGO_DSA, 255 ) },
		{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA2, 
		  MK_SIGHASHID( TLS_SIGALGO_DSA, TLS_HASHALGO_SHA2 ) },
		{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA1, 
		  MK_SIGHASHID( TLS_SIGALGO_DSA, TLS_HASHALGO_SHA1 ) },
#endif /* USE_DSA */
		/* ECDSA */
#ifdef USE_ECDSA
		{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHAng, 
		  MK_SIGHASHID( TLS_SIGALGO_ECDSA, 255 ) },
#ifdef CONFIG_SUITEB
		{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, 
		  MK_SIGHASHID( TLS_SIGALGO_ECDSA, TLS_HASHALGO_SHA384 ) },
#endif /* CONFIG_SUITEB */
		{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, 
		  MK_SIGHASHID( TLS_SIGALGO_ECDSA, TLS_HASHALGO_SHA2 ) },
#if 0	/* 2/11/11 Disabled option for SHA1 after poll on ietf-tls list */
		{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA1, 
		  MK_SIGHASHID( TLS_SIGALGO_ECDSA, TLS_HASHALGO_SHA1 ) },
#endif /* 0 */
#endif /* USE_ECDSA */
		{ CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, TLS_SIGALGO_NONE }, 
			{ CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, TLS_SIGALGO_NONE }
		};
	BYTE algoList[ 32 + 8 ];
	LOOP_INDEX i;
	int algoIndex = 0;

	/* Determine which signature and hash algorithms are available for use */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( algoTbl, SIG_HASH_INFO ) && \
				  algoTbl[ i ].sigAlgo != CRYPT_ALGO_NONE,
			  i++ )
		{
		CRYPT_ALGO_TYPE sigAlgo;
		int LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( algoTbl, \
														 SIG_HASH_INFO ) - 1 ) );

		/* If the given signature algorithm isn't enabled, skip any further
		   occurrences of this algorithm */
		sigAlgo = algoTbl[ i ].sigAlgo;
		if( !algoAvailable( sigAlgo ) )
			{
			LOOP_MED_CHECKINC_ALT( i < FAILSAFE_ARRAYSIZE( algoTbl, \
														   SIG_HASH_INFO ) && \
										algoTbl[ i ].sigAlgo == sigAlgo,
								   i++ )
				{
				ENSURES( LOOP_INVARIANT_MED_XXX_ALT( i, 0, 
													 FAILSAFE_ARRAYSIZE( algoTbl, \
																		 SIG_HASH_INFO ) - 1 ) );
				}
			ENSURES( LOOP_BOUND_OK_ALT );
			ENSURES( i < FAILSAFE_ARRAYSIZE( algoTbl, SIG_HASH_INFO ) );
			i--;	/* Adjust for increment also done in outer loop */

			continue;
			}

		/* If the hash algorithm isn't enabled, skip this entry */
		if( !algoAvailable( algoTbl[ i ].hashAlgo ) )
			continue;

		/* Add the TLS IDs for this signature and hash algorithm combination.  
		   Although the record is called SignatureAndHashAlgorithm, what's 
		   written first is the hash algorithm and not the signature 
		   algorithm */
		algoList[ algoIndex++ ] = intToByte( algoTbl[ i ].tlsSigHashID >> 8 );
		algoList[ algoIndex++ ] = intToByte( algoTbl[ i ].tlsSigHashID & 0xFF );
		ENSURES( algoIndex <= 32 );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( algoTbl, SIG_HASH_INFO ) );

	/* Write the combination of hash and signature algorithms */
	writeUint16( stream, algoIndex );
	return( swrite( stream, algoList, algoIndex ) );
	}

/****************************************************************************
*																			*
*							Read TLS Extensions								*
*																			*
****************************************************************************/

/* Read a single extension.  The internal structure of some of these things 
   shows that they were created by ASN.1 people... */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 6 ) ) \
static int readExtension( INOUT_PTR STREAM *stream, 
						  INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_RANGE( 0, 65536 ) const int type,
						  IN_LENGTH_SHORT_Z const int extLength,
						  OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
	int value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( type >= 0 && type <= 65536 );
	REQUIRES( isShortIntegerRange( extLength ) );

	/* Clear return values */
	*extErrorInfoSet = FALSE;

	switch( type )
		{
		case TLS_EXT_SNI:
			/* Read and process the SNI */
			return( readSNI( stream, handshakeInfo, extLength, 
							 isServer( sessionInfoPtr ) ? \
								TRUE : FALSE ) );

		case TLS_EXT_MAX_FRAGMENT_LENTH:
			{
/*			static const int fragmentTbl[] = \
					{ 0, 512, 1024, 2048, 4096, 8192, 16384, 16384 }; */

			/* Response: If fragment-size == 3...5, send same to peer.  Note 
			   that we also allow a fragment-size value of 5, which isn't 
			   specified in the standard but should probably be present 
			   since it would otherwise result in a missing value between 
			   4096 and the default of 16384:

				byte		fragmentLength */
			status = value = sgetc( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( value < 1 || value > 5 )
				return( CRYPT_ERROR_BADDATA );

/*			sessionInfoPtr->maxPacketSize = fragmentTbl[ value ]; */
			return( CRYPT_OK );
			}

		case TLS_EXT_SUPPORTED_GROUPS:
			{
			CRYPT_ECCCURVE_TYPE preferredCurveID;

			/* If we're using pure PSK then there's no ECC information 
			   (or a private key in general) available.  In theory we could
			   be using PSK + ECDH but that's unlikely so we assume the
			   absence of a private key means no ECC */
			if( sessionInfoPtr->privateKey == CRYPT_ERROR )
				{
				handshakeInfo->disableECC = TRUE;
				return( sSkip( stream, extLength, MAX_INTLENGTH_SHORT ) );
				}

			/* Read and process the list of preferred curves */
			status = readSupportedGroups( stream, sessionInfoPtr, 
										  extLength, &preferredCurveID,
										  extErrorInfoSet );
			if( cryptStatusError( status ) )
				return( status );

			/* If we couldn't find a curve that we have in common with the 
			   other side, disable the use of ECC algorithms.  This is a 
			   somewhat nasty failure mode because it means that something 
			   like a buggy implementation that sends the wrong hello 
			   extension (which is rather more likely than, say, an 
			   implementation not supporting the de facto universal-standard 
			   NIST curves) means that the crypto is quietly switched to 
			   non-ECC with the user being none the wiser, but there's no 
			   way for an implementation to negotiate ECC-only encryption */
			if( preferredCurveID == CRYPT_ECCCURVE_NONE )
				handshakeInfo->disableECC = TRUE;
			else
				handshakeInfo->eccCurveID = preferredCurveID;

			return( CRYPT_OK );
			}

		case TLS_EXT_EC_POINT_FORMATS:
			/* We don't really need to process this extension because every 
			   implementation is required to support uncompressed points (it 
			   also seems to be the universal standard that everyone uses by 
			   default anyway) so all that we do is treat the presence of 
			   the overall extension as an indicator that we should send 
			   back our own one in the server hello:

				byte		pointFormatListLength
				byte[]		pointFormat */
			if( extLength > 0 )
				{
				status = sSkip( stream, extLength, MAX_INTLENGTH_SHORT );
				if( cryptStatusError( status ) )
					return( status );
				}
			handshakeInfo->sendECCPointExtn = TRUE;

			return( CRYPT_OK );

		case TLS_EXT_SIGNATURE_ALGORITHMS:
			/* Read and process the list of signature algorithms */
			return( readSignatureAlgos( stream, sessionInfoPtr, 
										handshakeInfo, extLength, 
										extErrorInfoSet ) );

		case TLS_EXT_SECURE_RENEG:
			/* If we get a nonzero length for this extension (the '1' is the 
			   initial length byte at the start) then it's an indication of 
			   an attack.  The status code to return here is a bit 
			   uncertain, but CRYPT_ERROR_INVALID seems to be the least
			   inappropriate */
			if( extLength != 1 || sgetc( stream ) != 0 )
				return( CRYPT_ERROR_INVALID );

			/* If we're the server, remember that we have to echo the 
			   extension back to the client */
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->needRenegResponse = TRUE;

			return( CRYPT_OK );

		case TLS_EXT_ENCTHENMAC:
			if( extLength != 0 )
				return( CRYPT_ERROR_INVALID );

			/* Turn on encrypt-then-MAC and, if we're the server, rememeber 
			   that we have to echo the extension back to the client */
			SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_ENCTHENMAC );
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->needEncThenMACResponse = TRUE;
			
			return( CRYPT_OK );

		case TLS_EXT_EMS:
			if( extLength != 0 )
				return( CRYPT_ERROR_INVALID );

			/* Turn on extended master secret handling */
			SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_EMS );
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->needEMSResponse = TRUE;
			return( CRYPT_OK );

		case TLS_EXT_TLS12LTS:
			if( extLength != 0 )
				return( CRYPT_ERROR_INVALID );

			/* Turn on TLS 1.2 LTS use.  This option implicitly includes 
			   encrypt-then-MAC and extended master secret, but we can't set 
			   these yet since that would result in us sending spurious 
			   response extensions if LTS was present in a request but the 
			   others weren't */
			SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_TLS12LTS );
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->needTLS12LTSResponse = TRUE;
			return( CRYPT_OK );

		case TLS_EXT_SUPPORTED_VERSIONS:
			/* Read and process the version information */
			return( readSupportedVersions( stream, sessionInfoPtr, 
										   extLength ) );

#ifdef USE_TLS13
		case TLS_EXT_KEY_SHARE:
			/* If we're using pure PSK then we can't do anything with the
			   keyex data */
			if( isServer( sessionInfoPtr ) && \
				sessionInfoPtr->privateKey == CRYPT_ERROR )
				{
				DEBUG_PRINT(( "Server is using pure PSK, ignoring keyex "
							  "extension.\n" ));
				handshakeInfo->disableECC = TRUE;
				return( sSkip( stream, extLength, MAX_INTLENGTH_SHORT ) );
				}

			/* Read and process the keyex information */
			return( readKeyexTLS13( sessionInfoPtr, handshakeInfo, stream, 
									extLength, extErrorInfoSet ) );
#endif /* USE_TLS13 */

		default:
			/* Check for more Google brain damage, see the comment in
			   readSupportedVersions() */
			if( ( type >> 8 ) == ( type & 0xFF ) && extLength == 0 )
				{
				DEBUG_PRINT(( "  Google braindamage detected, skipping "
							  "gibberish extension %d (%X).\n", 
							  type, type ));
				return( CRYPT_OK );
				}

			/* Default: Ignore the extension */
			if( extLength > 0 )
				{
				status = sSkip( stream, extLength, MAX_INTLENGTH_SHORT );
				if( cryptStatusError( status ) )
					return( status );
				}

			return( CRYPT_OK );
		}

	retIntError();
	}

/* Read TLS extensions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readExtensions( INOUT_PTR STREAM *stream, 
					INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					IN_LENGTH_SHORT const int length )
	{
	const int endPos = stell( stream ) + length;
	LOOP_INDEX noExtensions;
	int extensionSeen[ MAX_EXTENSIONS + 8 ];
	int extListLen, extensionSeenLast = 0;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );
	REQUIRES( isShortIntegerRangeMin( endPos, length ) );

	/* Read the extension header and make sure that it's valid:

		uint16		extListLen
			uint16	extType
			uint16	extLen
			byte[]	extData 

	   We can get zero-length extensions so we can't take the precaution of 
	   requiring at least one byte of payload data as a sanity check */
	if( length < UINT16_SIZE + UINT16_SIZE + UINT16_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "TLS hello contains %d bytes extraneous data", length ) );
		}
	status = extListLen = readUint16( stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid TLS extension information" ) );
		}
	if( extListLen != length - UINT16_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid TLS extension data length %d, should be %d",
				  extListLen, length - UINT16_SIZE ) );
		}

	/* Process the extensions */
	LOOP_MED( noExtensions = 0,
			  noExtensions < MAX_EXTENSIONS && stell( stream ) < endPos, 
			  noExtensions++ )
		{
		const EXT_CHECK_INFO *extCheckInfoPtr = NULL;
		BOOLEAN extErrorInfoSet;
		LOOP_INDEX_ALT i;
		int type, extLen DUMMY_INIT;

		ENSURES( LOOP_INVARIANT_MED( noExtensions, 0, MAX_EXTENSIONS - 1 ) );

		/* Read the header for the next extension and get the extension-
		   checking information.  The length check at this point is just a
		   generic sanity check, more specific checking is done once we've 
		   got the extension type-specific information */
		type = readUint16( stream );
		status = extLen = readUint16( stream );
		if( cryptStatusError( status ) || \
			!isShortIntegerRange( extLen ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid TLS extension list item header" ) );
			}
		LOOP_LARGE_ALT( i = 0,
						i < FAILSAFE_ARRAYSIZE( extCheckInfoTbl, \
												EXT_CHECK_INFO ) && \
							extCheckInfoTbl[ i ].type != CRYPT_ERROR,
					    i++ )
			{
			ENSURES( LOOP_INVARIANT_LARGE_ALT( i, 0, 
											   FAILSAFE_ARRAYSIZE( extCheckInfoTbl, \
																   EXT_CHECK_INFO ) - 1 ) );

			if( extCheckInfoTbl[ i ].type == type )
				{
				extCheckInfoPtr = &extCheckInfoTbl[ i ];
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		ENSURES( i < FAILSAFE_ARRAYSIZE( extCheckInfoTbl, EXT_CHECK_INFO ) ); 
		if( extCheckInfoPtr != NULL )
			{
			const int minLength = isServer( sessionInfoPtr ) ? \
						extCheckInfoPtr->minLengthClient : \
						extCheckInfoPtr->minLengthServer;

			/* Perform any necessary initial checking of the extension */
			if( minLength == CRYPT_ERROR )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Received disallowed TLS %s extension from %s", 
						  extCheckInfoPtr->description, 
						  isServer( sessionInfoPtr ) ? "server" : "client" ) );
				}
			if( extLen < minLength || extLen > extCheckInfoPtr->maxLength )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid TLS %s extension length %d, should be "
						  "%d...%d", extCheckInfoPtr->description, extLen,
						  minLength, extCheckInfoPtr->maxLength ) );
				}

			/* Make sure that we haven't already seen this extension.  Note 
			   that we only perform this check for known extensions, since 
			   we don't know whether new/unknown extensions may be allowed 
			   in duplicate form or not */
			LOOP_EXT_ALT( i = 0, i < extensionSeenLast && \
								 i < MAX_EXTENSIONS, i++, MAX_EXTENSIONS )
				{
				ENSURES( LOOP_INVARIANT_EXT_ALT( i, 0, MAX_EXTENSIONS - 1, \
												 MAX_EXTENSIONS ) );

				if( extensionSeen[ i ] == type )
					{
					retExt( CRYPT_ERROR_BADDATA,
							( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
							  "Duplicate TLS %s extension encountered", 
							  extCheckInfoPtr->description ) );
					}
				}
			ENSURES( LOOP_BOUND_OK_ALT );
			ENSURES( i <= MAX_EXTENSIONS );
			extensionSeen[ extensionSeenLast++ ] = type;
			}
		DEBUG_PRINT(( "Read extension TLS %s (%d), length %d.\n",
					  ( extCheckInfoPtr != NULL ) ? \
						extCheckInfoPtr->description : "<Unknown>", 
					  type, extLen ));
		DEBUG_DUMP_STREAM( stream, stell( stream ), extLen );

		/* Process the extension data */
		status = readExtension( stream, sessionInfoPtr, handshakeInfo, 
								type, extLen, &extErrorInfoSet );
		if( cryptStatusError( status ) )
			{
			if( isInternalError( status ) )
				{
				/* If it's an internal error then we can't rely on the value
				   of the by-reference parameters */
				return( status );
				}
			if( extErrorInfoSet )
				return( status );
			if( extCheckInfoPtr != NULL )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid TLS %s extension data", 
						  extCheckInfoPtr->description ) );
				}
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid TLS extension data for extension "
					  "type %d", type ) );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	if( noExtensions >= MAX_EXTENSIONS )
		{
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "Excessive number (more than %d) of TLS extensions "
				  "encountered", noExtensions ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Write TLS Extensions							*
*																			*
****************************************************************************/

/* Write TLS extensions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeClientExtensions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM nullStream;
	const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );
	const TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	int serverNameHdrLen = 0, serverNameExtLen = 0;
	int supportedVersionsHdrLen = 0, supportedVersionsExtLen = 0;
	int sigHashHdrLen = 0, sigHashExtLen = 0;
	int supportedGroupsHdrLen = 0, supportedGroupsExtLen = 0;
	int pointFormatHdrLen = 0, pointFormatExtLen = 0;
	int pskModeHdrLen = 0, pskModeExtLen = 0;
	int keyexHdrLen = 0, keyexExtLen = 0;
	int minVersion, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS );
	REQUIRES( protocolInfo != NULL );

	/* Get the minimum protocol version, we have to do this at this point 
	   after ensuring that protocolInfo is valid */
	minVersion = ( tlsInfo->minVersion > 0 ) ? \
				 tlsInfo->minVersion : protocolInfo->minVersion;

	/* Determine the overall length of the extension data, first the server 
	   name indication (SNI) if it's present (it may not be if we're using
	   a raw network socket) */
	if( findSessionInfo( sessionInfoPtr,
						 CRYPT_SESSINFO_SERVER_NAME ) != NULL )
		{
		serverNameHdrLen = UINT16_SIZE + UINT16_SIZE;
		sMemNullOpen( &nullStream );
		status = writeSNI( &nullStream, sessionInfoPtr );
		if( cryptStatusOK( status ) )
			{
			serverNameExtLen = stell( &nullStream );
			REQUIRES( isShortIntegerRangeNZ( serverNameExtLen ) );
			}
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* TLS 1.3 supported versions */
	supportedVersionsHdrLen = UINT16_SIZE + UINT16_SIZE;
	sMemNullOpen( &nullStream );
	status = writeSupportedVersions( &nullStream, sessionInfoPtr, 
									 minVersion );
	if( cryptStatusOK( status ) )
		{
		supportedVersionsExtLen = stell( &nullStream );
		REQUIRES( isShortIntegerRangeNZ( supportedVersionsExtLen ) );
		}
	sMemClose( &nullStream );
	if( cryptStatusError( status ) )
		return( status );

	/* Signature and hash algorithms.  These are only used with TLS 1.2+ so 
	   we only write them if we're using these versions of the protocol */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		sigHashHdrLen = UINT16_SIZE + UINT16_SIZE;
		sMemNullOpen( &nullStream );
		status = writeSignatureAlgos( &nullStream );
		if( cryptStatusOK( status ) )
			{
			sigHashExtLen = stell( &nullStream );
			REQUIRES( isShortIntegerRangeNZ( sigHashExtLen ) );
			}
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* ECC information.  This is only sent if we're proposing ECC suites in
	   the client hello */
	if( algoAvailable( CRYPT_ALGO_ECDH ) )
		{
		supportedGroupsHdrLen = UINT16_SIZE + UINT16_SIZE;
		sMemNullOpen( &nullStream );
		status = writeSupportedGroups( &nullStream, sessionInfoPtr );
		if( cryptStatusOK( status ) )
			{
			supportedGroupsExtLen = stell( &nullStream );
			REQUIRES( isShortIntegerRangeNZ( supportedGroupsExtLen ) );
			}
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );

		/* The point-format extension is fixed-length so we just hardcode 
		   the length information here */
		pointFormatHdrLen = UINT16_SIZE + UINT16_SIZE;
		pointFormatExtLen = 1 + 1;
		}

	/* TLS 1.3-only extensions */
#ifdef USE_TLS13
	/* PSK modes, TLS 1.3's version of session resumption */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		pskModeHdrLen = UINT16_SIZE + UINT16_SIZE;
		pskModeExtLen = 1 + 1;
		}

	/* Keyex inforation, which in TLS 1.3 is stuffed into an extension in 
	   the client hello rather than being sent as an actual keyex */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		keyexHdrLen = UINT16_SIZE + UINT16_SIZE;
		sMemNullOpen( &nullStream );
		status = writeKeyexTLS13( &nullStream, handshakeInfo, FALSE );
		if( cryptStatusOK( status ) )
			{
			keyexExtLen = stell( &nullStream );
			REQUIRES( isShortIntegerRangeNZ( keyexExtLen ) );
			}
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_TLS13 */

	/* Write the list of extensions */
	writeUint16( stream, serverNameHdrLen + serverNameExtLen + \
						 supportedVersionsHdrLen + supportedVersionsExtLen + \
						 RENEG_EXT_SIZE +					/* Renegotiation */
						 ( UINT16_SIZE + UINT16_SIZE ) +	/* EncThenMAC */
						 ( UINT16_SIZE + UINT16_SIZE ) +	/* Extended MS */
						 ( UINT16_SIZE + UINT16_SIZE ) +	/* TLS 1.2 LTS */
						 sigHashHdrLen + sigHashExtLen + \
						 supportedGroupsHdrLen + supportedGroupsExtLen + \
						 pointFormatHdrLen + pointFormatExtLen + \
						 pskModeHdrLen + pskModeExtLen + \
						 keyexHdrLen + keyexExtLen );
	if( serverNameHdrLen > 0 )
		{
		writeUint16( stream, TLS_EXT_SNI );
		writeUint16( stream, serverNameExtLen );
		status = writeSNI( stream, sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension server name indication (%d), length %d.\n",
					  TLS_EXT_SNI, serverNameExtLen ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - serverNameExtLen, 
						   serverNameExtLen );
		}
	if( supportedVersionsHdrLen > 0 )
		{
		writeUint16( stream, TLS_EXT_SUPPORTED_VERSIONS );
		writeUint16( stream, supportedVersionsExtLen );
		status = writeSupportedVersions( stream, sessionInfoPtr, minVersion );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension supported versions (%d), length %d.\n",
					  TLS_EXT_SUPPORTED_VERSIONS, supportedVersionsExtLen ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - supportedVersionsExtLen, 
						   supportedVersionsExtLen );
		}
	status = swrite( stream, RENEG_EXT_DATA, RENEG_EXT_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT(( "Wrote extension secure renegotiation (%d), length 1.\n",
				  TLS_EXT_SECURE_RENEG ));
	DEBUG_DUMP_STREAM( stream, stell( stream ) - 1, 1 );
	writeUint16( stream, TLS_EXT_ENCTHENMAC );
	status = writeUint16( stream, 0 );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT(( "Wrote extension encrypt-then-MAC (%d), length 0.\n",
				  TLS_EXT_ENCTHENMAC ));
	writeUint16( stream, TLS_EXT_EMS );
	status = writeUint16( stream, 0 );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT(( "Wrote extension extended Master Secret (%d), length 0.\n",
				  TLS_EXT_EMS ));
	writeUint16( stream, TLS_EXT_TLS12LTS );
	status = writeUint16( stream, 0 );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT(( "Wrote extension TLS 1.2 LTS (%d), length 0.\n",
				  TLS_EXT_TLS12LTS ));
	if( sigHashExtLen > 0 )
		{
		/* Write the signature+hash algorithms extension */
		writeUint16( stream, TLS_EXT_SIGNATURE_ALGORITHMS );
		writeUint16( stream, sigHashExtLen );
		status = writeSignatureAlgos( stream );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension signature algorithm (%d), length %d.\n",
					  TLS_EXT_SIGNATURE_ALGORITHMS, sigHashExtLen ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - sigHashExtLen, 
						   sigHashExtLen );
		}
	if( supportedGroupsExtLen > 0 )
		{
		/* Write the supported groups extension */
		writeUint16( stream, TLS_EXT_SUPPORTED_GROUPS );
		writeUint16( stream, supportedGroupsExtLen );
		status = writeSupportedGroups( stream, sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension supported groups (%d), length %d.\n",
					  TLS_EXT_SUPPORTED_GROUPS, supportedGroupsExtLen ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - supportedGroupsExtLen, 
						   supportedGroupsExtLen );

		/* Write the ECC point format extension */
		writeUint16( stream, TLS_EXT_EC_POINT_FORMATS );
		writeUint16( stream, pointFormatExtLen );
		sputc( stream, 1 );						/* Point-format list len.*/
		status = sputc( stream, 0 );			/* Uncompressed points */
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension ECC point format (%d), length %d.\n",
					  TLS_EXT_EC_POINT_FORMATS, 1 + 1 ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - ( 1 + 1 ), 1 + 1 );
		}
#ifdef USE_TLS13
	if( pskModeHdrLen > 0 )
		{
		/* Write the TLS 1.3 PSK modes extension.  This extension, 
		   psk_key_exchange_modes, must be sent if the pre_shared_key 
		   extension is sent.  In other words the PSK information is split 
		   across two different extensions for no known reason, with 
		   incredibly complex and awkward rules (RFC 8446 section 
		   4.2.9/4.2.11) for the server reconciling the two after the 
		   client has split them up */
		writeUint16( stream, TLS_EXT_PSK_KEYEX_MODES );
		writeUint16( stream, pskModeExtLen );
		sputc( stream, 1 );
		status = sputc( stream, TLS_PSK_STANDARD );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension PSK modes (%d), length %d.\n",
					  TLS_EXT_PSK_KEYEX_MODES, pskModeExtLen ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - pskModeExtLen, 
						   pskModeExtLen );
		}
	if( keyexExtLen > 0 )
		{
		/* Write the TLS 1.3 keyex extension */
		writeUint16( stream, TLS_EXT_KEY_SHARE );
		writeUint16( stream, keyexExtLen );
		status = writeKeyexTLS13( stream, handshakeInfo, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension keyex (%d), length %d.\n",
					  TLS_EXT_KEY_SHARE, keyexExtLen ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - keyexExtLen, 
						   keyexExtLen );
		}
#endif /* USE_TLS13 */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeServerExtensions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	const BOOLEAN isTLS13 = \
			( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ) ? \
			TRUE : FALSE;
	int keyexHdrLen = 0, keyexExtLen = 0;
	int extListLen = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS );

	/* Calculate the size of the extensions.  Unlike the client extensions,
	   most of these are just signalling values that acknowledge the 
	   corresponding client extensions or have a single byte of fixed length 
	   so we don't need to explicitly calculate payload lengths.
	   
	   TLS 1.3 doesn't send a lot of the usual extensions, the extension
	   read code manages this by clearing the various needXXX flags, however
	   the SNI response is still sent but in the encrypted extensions rather
	   than the standard extensions so we explicitly check for sending it
	   here */
	if( handshakeInfo->needSNIResponse && !isTLS13 )
		extListLen += UINT16_SIZE + UINT16_SIZE;
	if( handshakeInfo->needRenegResponse )
		extListLen += RENEG_EXT_SIZE;
	if( handshakeInfo->needEncThenMACResponse )
		extListLen += UINT16_SIZE + UINT16_SIZE;
	if( handshakeInfo->needEMSResponse )
		extListLen += UINT16_SIZE + UINT16_SIZE;
	if( handshakeInfo->needTLS12LTSResponse )
		extListLen += UINT16_SIZE + UINT16_SIZE;
#ifdef USE_TLS13
	if( isTLS13 )
		extListLen += UINT16_SIZE + UINT16_SIZE + UINT16_SIZE;
#endif /* USE_TLS13 */
	if( isEccAlgo( handshakeInfo->keyexAlgo ) && \
		handshakeInfo->sendECCPointExtn )
		extListLen += UINT16_SIZE + UINT16_SIZE + 1 + 1;
#ifdef USE_TLS13
	if( isTLS13 )
		{
		STREAM nullStream;

		keyexHdrLen = UINT16_SIZE + UINT16_SIZE;
		sMemNullOpen( &nullStream );
		status = writeKeyexTLS13( &nullStream, handshakeInfo, TRUE );
		if( cryptStatusOK( status ) )
			{
			keyexExtLen = stell( &nullStream );
			REQUIRES( isShortIntegerRangeNZ( keyexExtLen ) );
			}
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_TLS13 */
	if( extListLen + keyexHdrLen <= 0 )
		{
		/* No extensions to write, we're done */
		return( CRYPT_OK );
		}

	/* Write the overall extension list length */
	writeUint16( stream, extListLen + keyexHdrLen + keyexExtLen );

	/* If the client sent an SNI extension then we have to acknowledge it
	   with a zero-length SNI extension response.  In most cases, in which
	   the caller hasn't set TLS_PFLAG_SERVER_SNI, this is slightly 
	   dishonest because we haven't passed the SNI data back to the caller,
	   but is typically sent by default by clients and since we're highly 
	   unlikely to be used with multihomed servers but likely to be used in 
	   oddball environments like ones without DNS we just accept any SNI 
	   and allow a connect.  In the case where the caller has set 
	   TLS_PFLAG_SERVER_SNI, we handle the SNI-based server-key switching in 
	   the server code so this response is also appropriate there */
	if( handshakeInfo->needSNIResponse && !isTLS13 )
		{
		writeUint16( stream, TLS_EXT_SNI );
		status = writeUint16( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension server name indication (%d), "
					  "length 0.\n", TLS_EXT_SNI, 0 ));
		}

	/* If the client sent a secure-renegotiation indicator we have to send a
	   response even though we don't support renegotiation.  See the comment 
	   by extCheckInfoTbl for why this odd behaviour is necessary */
	if( handshakeInfo->needRenegResponse )
		{
		status = swrite( stream, RENEG_EXT_DATA, RENEG_EXT_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension secure renegotiation (%d), length 1.\n",
					  TLS_EXT_SECURE_RENEG ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - 1, 1 );
		}

	/* If the client sent various request indicators, acknowledge them */
	if( handshakeInfo->needEncThenMACResponse )
		{
		writeUint16( stream, TLS_EXT_ENCTHENMAC );
		status = writeUint16( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension encrypt-then-MAC (%d), length 0.\n", 
					  TLS_EXT_ENCTHENMAC, 0 ));
		}
	if( handshakeInfo->needEMSResponse )
		{
		writeUint16( stream, TLS_EXT_EMS );
		status = writeUint16( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension extended Master Secret (%d), length 0.\n", 
					  TLS_EXT_EMS, 0 ));
		}
	if( handshakeInfo->needTLS12LTSResponse )
		{
		writeUint16( stream, TLS_EXT_TLS12LTS );
		status = writeUint16( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension TLS 1.2 LTS (%d), length 0.\n", 
					  TLS_EXT_TLS12LTS, 0 ));
		}
#ifdef USE_TLS13
	if( isTLS13 )
		{
		/* Supported versions, can only be written if we're talking TLS 1.3 
		   (RFC 8446 section 4.2.1) */
		writeUint16( stream, TLS_EXT_SUPPORTED_VERSIONS );
		writeUint16( stream, UINT16_SIZE );
		status = writeUint16( stream, ( TLS_MAJOR_VERSION << 8 ) | \
										TLS_MINOR_VERSION_TLS13 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension suported versions (%d), length 2.\n", 
					  TLS_MINOR_VERSION_TLS13 ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - UINT16_SIZE, 
						   UINT16_SIZE );
		}
#endif /* USE_TLS13 */

	/* If the client sent ECC extensions and we've negotiated an ECC cipher 
	   suite, send back the appropriate response.  We don't have to send 
	   back the curve ID that we've chosen because this is communicated 
	   explicitly in the server keyex */
	if( isEccAlgo( handshakeInfo->keyexAlgo ) && \
		handshakeInfo->sendECCPointExtn )
		{
		writeUint16( stream, TLS_EXT_EC_POINT_FORMATS );
		writeUint16( stream, 1 + 1 );	/* Extn. length */
		sputc( stream, 1 );				/* Point-format list len.*/
		status = sputc( stream, 0 );	/* Uncompressed points */
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension ECC point format (%d), length 2.\n",
					  TLS_EXT_EC_POINT_FORMATS ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - 1 + 1, 1 + 1 );
		}

	/* If we're using TLS 1.3 then we have to send back a keyex extension */
#ifdef USE_TLS13
	if( keyexExtLen > 0 )
		{
		/* Write the TLS 1.3 keyex extension */
		writeUint16( stream, TLS_EXT_KEY_SHARE );
		writeUint16( stream, keyexExtLen );
		status = writeKeyexTLS13( stream, handshakeInfo, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension keyex (%d), length %d.\n",
					  TLS_EXT_KEY_SHARE, keyexExtLen ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - keyexExtLen, 
						   keyexExtLen );
		}
#endif /* USE_TLS13 */

	return( CRYPT_OK );
	}
#endif /* USE_TLS */
