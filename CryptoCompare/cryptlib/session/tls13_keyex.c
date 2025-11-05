/****************************************************************************
*																			*
*					cryptlib TLS 1.3 Keyex Management						*
*					Copyright Peter Gutmann 2019-2021						*
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

#ifdef USE_TLS13

/****************************************************************************
*																			*
*								Read/Write Keyex Data						*
*																			*
****************************************************************************/

/* The TLS 1.3 keyex is stuffed inside an extension in the client/server 
   hello.  This is an ugly "optimisation" for TLS 1.3 where we have to guess 
   any keyex mechanisms that the server supports and send one of each that 
   we think might be required, with the server choosing the one that it 
   deems the most cromulent.  
   
   This saves 1RTT at the expense of a whole lot of extra crypto computation 
   on the client, and to make things even worse since we're taking guesses 
   at what's required we have to send this even if we're doing a PSK-based
   session resume because we don't know at this point whether the server 
   will allow the resume or not.  This pretty much defeats the whole point 
   of doing a resume since all of the crypto is still done whether it's 
   needed or not.

  [	uint16			keyexListLength		-- Client only ]
		uint16		namedGroup
		uint16		keyexLength
			byte[]	keyex

   For DH the keyex is the Y value padded out with zeroes to the length of 
   p for no known reason, for ECDH it's the ECC point in X9.62 format */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readKeyexTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					INOUT_PTR STREAM *stream, 
					IN_LENGTH_SHORT_Z const int extLength,
					OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
	static const int eccCurveInfo[] = {
#ifdef PREFER_ECC
		TLS_GROUP_SECP256R1,		/* CRYPT_ECCCURVE_P256 */
		TLS_GROUP_BRAINPOOLP256R1,	/* CRYPT_ECCCURVE_BRAINPOOL_P256 */
		TLS_GROUP_FFDHE2048,		/* 2048-bit DH */
		TLS_GROUP_FFDHE3072,		/* 3096-bit DH */
	 /* TLS_GROUP_FFDHE4096,		// Pointlessly large group */
#else
		TLS_GROUP_FFDHE2048,		/* 2048-bit DH */
		TLS_GROUP_FFDHE3072,		/* 3096-bit DH */
	 /* TLS_GROUP_FFDHE4096,		// Pointlessly large group */
		TLS_GROUP_SECP256R1,		/* CRYPT_ECCCURVE_P256 */
		TLS_GROUP_BRAINPOOLP256R1,	/* CRYPT_ECCCURVE_BRAINPOOL_P256 */
#endif /* PREFER_ECC */
#ifdef USE_SHA2_EXT
		TLS_GROUP_SECP384R1,		/* CRYPT_ECCCURVE_P384 */
		TLS_GROUP_SECP521R1,		/* CRYPT_ECCCURVE_P521 */
		TLS_GROUP_BRAINPOOLP384R1,	/* CRYPT_ECCCURVE_BRAINPOOL_P384 */
		TLS_GROUP_BRAINPOOLP512R1,	/* CRYPT_ECCCURVE_BRAINPOOL_P512 */
#endif /* USE_SHA2_EXT */
			TLS_GROUP_NONE, TLS_GROUP_NONE 
		};
	static const MAP_TABLE curveIDTbl[] = {
		{ TLS_GROUP_FFDHE2048, bitsToBytes( 2048 ) },
		{ TLS_GROUP_FFDHE3072, bitsToBytes( 3072 ) },
	 /* { TLS_GROUP_FFDHE4096, bitsToBytes( 4096 ) }, */
		{ TLS_GROUP_SECP256R1, CRYPT_ECCCURVE_P256 },
		{ TLS_GROUP_SECP384R1, CRYPT_ECCCURVE_P384 },
		{ TLS_GROUP_SECP521R1, CRYPT_ECCCURVE_P521 },
		{ TLS_GROUP_BRAINPOOLP256R1, CRYPT_ECCCURVE_BRAINPOOL_P256 },
		{ TLS_GROUP_BRAINPOOLP384R1, CRYPT_ECCCURVE_BRAINPOOL_P384 },
		{ TLS_GROUP_BRAINPOOLP512R1, CRYPT_ECCCURVE_BRAINPOOL_P512 },
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	CRYPT_ECCCURVE_TYPE clientECDHcurve = CRYPT_ECCCURVE_NONE;
	const BOOLEAN isEccAvailable = \
					algoAvailable( CRYPT_ALGO_ECDH ) ? TRUE : FALSE;
	BOOLEAN isEccKeyex = FALSE, isGoogle = FALSE;
	int clientDHkeySize = CRYPT_ERROR, keyexListLen = extLength;
	int keyexParam = CRYPT_ERROR, groupIndex = 99, endPos, status;
	LOOP_INDEX i;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRange( extLength ) );

	/* Clear return values */
	*extErrorInfoSet = FALSE;

	/* If we're the client, get the keyex parameters that we used when we 
	   sent our keyex to the server */
#ifndef CONFIG_FUZZ
	if( !isServer( sessionInfoPtr ) )
		{
		int eccParam;

		/* Get the DH keysize and ECDH curve type */
		status = krnlSendMessage( handshakeInfo->dhContext,
								  IMESSAGE_GETATTRIBUTE, &clientDHkeySize,
								  CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusOK( status ) && \
			handshakeInfo->dhContextAlt != CRYPT_ERROR )
			{
			status = krnlSendMessage( handshakeInfo->dhContextAlt,
									  IMESSAGE_GETATTRIBUTE, &eccParam,
									  CRYPT_IATTRIBUTE_KEY_ECCPARAM );
			if( cryptStatusOK( status ) )
				clientECDHcurve = eccParam;	/* int vs. enum */
			}
		if( cryptStatusError( status ) )
			return( status );
		}
#else
	/* Set up dummy parameters */
	clientDHkeySize = bitsToBytes( 2048 );
	clientECDHcurve = CRYPT_ECCCURVE_P256;
#endif /* CONFIG_FUZZ */

	/* If we're the server, the client will send us a list of keyex values 
	   so first we need to read and check the list header.  If we're the 
	   client then there's a single value of the same length as the 
	   extension */
	if( isServer( sessionInfoPtr ) )
		{
		status = keyexListLen = readUint16( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( keyexListLen != extLength - UINT16_SIZE )
			return( CRYPT_ERROR_BADDATA );
		}
	if( keyexListLen < UINT16_SIZE + UINT16_SIZE + 32 || \
		keyexListLen > 1024 )
		return( CRYPT_ERROR_BADDATA );

	/* Iterate through the keyex values */
	endPos = stell( stream ) + keyexListLen;
	ENSURES( isIntegerRangeMin( endPos, keyexListLen ) );
	LOOP_SMALL( i = 0, stell( stream ) < endPos - 16 && i < 8, i++ )
		{
		int namedGroup, groupParam, keyexStartPos DUMMY_INIT, keyexLength;
		LOOP_INDEX_ALT newGroupIndex;

		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 7 ) );

		/* Read the group ID and keyex data length.  At this point we can 
		   run into more Google braindamage, see the comment in 
		   tls_ext.c:readSupportedVersions(), which we detect in the same
		   way as we do there, by checking for a first entry having a named 
		   group with same invalid value in the high and low 8 bits */
		status = namedGroup = readUint16( stream );
		if( !cryptStatusError( status ) )
			keyexStartPos = stell( stream );
		status = keyexLength = readUint16( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( keyexLength < 32 || keyexLength > CRYPT_MAX_PKCSIZE )
			{
			/* It's an invalid value, make sure that it's not just Google
			   braindamage.  We check for a length value 1...31 since to get
			   here it must have been < 32 */
			if( i == 0 && \
				( namedGroup >> 8 ) == ( namedGroup & 0xFF ) && \
				keyexLength >= 1 && keyexLength < 32 )
				{
				DEBUG_PRINT(( "  Google braindamage detected, skipping "
							  "gibberish named group %X, length %d.\n", 
							  namedGroup, keyexLength ));
				status = sSkip( stream, keyexLength, MAX_INTLENGTH_SHORT );
				if( cryptStatusError( status ) )
					return( status );
				isGoogle = TRUE;
				continue;
				}

			return( CRYPT_ERROR_BADDATA );
			}

		/* If this is an ECC group and we don't have ECC available, 
		   continue */
		if( isECCGroup( namedGroup ) && !isEccAvailable )
			{
			status = sSkip( stream, keyexLength, MAX_INTLENGTH_SHORT );
			if( cryptStatusError( status ) )
				return( status );
			continue;
			}

		/* Check whether this is a more-preferred group than what we've 
		   currently got.  First, we find its position in the preferred-
		   groups array */
		LOOP_SMALL_ALT( newGroupIndex = 0, 
						newGroupIndex < FAILSAFE_ARRAYSIZE( eccCurveInfo, int ) && \
						eccCurveInfo[ newGroupIndex ] != namedGroup && \
						eccCurveInfo[ newGroupIndex ] != TLS_GROUP_NONE,
						newGroupIndex++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL_ALT( newGroupIndex, 0, 
											   FAILSAFE_ARRAYSIZE( eccCurveInfo, int ) - 1 ) );
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		ENSURES( newGroupIndex <= FAILSAFE_ARRAYSIZE( eccCurveInfo, int ) );

		/* If we didn't find a match or haven't found something more 
		   preferred than what we've already got, continue */
		if( eccCurveInfo[ newGroupIndex ] == TLS_GROUP_NONE || \
			newGroupIndex > groupIndex )
			{
			status = sSkip( stream, keyexLength, MAX_INTLENGTH_SHORT );
			if( cryptStatusError( status ) )
				return( status );
			continue;
			}

		/* Get the information for this group, either the DH key size or the 
		   ECDH curve type */
		status = mapValue( namedGroup, &groupParam, curveIDTbl, 
						   FAILSAFE_ARRAYSIZE( curveIDTbl, MAP_TABLE ) );
		ENSURES( cryptStatusOK( status ) );

		/* If we're the client then the returned keyex value has to match 
		   what we sent, not just be something that we recognise */
		if( !isServer( sessionInfoPtr ) )
			{
			if( isECCGroup( namedGroup ) )
				{
				if( groupParam != clientECDHcurve )
					{
					*extErrorInfoSet = TRUE;
					retExt( CRYPT_ERROR_INVALID,
							( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
							  "Server sent keyex for ECC group %d, we "
							  "requested group %d", groupParam, 
							  clientECDHcurve ) );
					}
				}
			else
				{
				if( groupParam != clientDHkeySize )
					{
					*extErrorInfoSet = TRUE;
					retExt( CRYPT_ERROR_INVALID,
							( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
							  "Server sent keyex for DH keysize %d, we "
							  "requested keysize %d", groupParam, 
							  clientDHkeySize ) );
					}
				}
			}

		/* Remember the keyex data.  This gets a bit complicated both 
		   because we need to include the length value with the data and
		   because classic TLS used an 8-bit length for ECC keyex data for 
		   no known reason while TLS 1.3 uses a standard 16-bit length.  To 
		   deal with this we skip the first byte of the 16-bit length to 
		   make it look like an 8-bit length if we're reading an ECC keyex 
		   value */
		groupIndex = newGroupIndex;
		keyexParam = groupParam;
		handshakeInfo->tls13KeyexGroup = namedGroup;
		if( isECCGroup( namedGroup ) )
			{
			/* Make sure that the result will fit into an 8-bit length,
			   required for classic TLS ECC values */
			if( keyexLength > 256 )
				return( CRYPT_ERROR_BADDATA );

			isEccKeyex = TRUE;
			keyexLength += 1;			/* Single-byte length */
			status = sseek( stream, keyexStartPos + 1 );
			}
		else
			{
			keyexLength += UINT16_SIZE;	/* 16-bit length */
			status = sseek( stream, keyexStartPos );
			}
		if( cryptStatusOK( status ) )
			{
			status = sread( stream, handshakeInfo->tls13KeyexValue, 
							keyexLength );
			}
		if( cryptStatusError( status ) )
			return( status );
		handshakeInfo->tls13KeyexValueLen = keyexLength;
		}
	ENSURES( LOOP_BOUND_OK );

	/* If we didn't match anything that we can use, we can't continue */
	if( keyexParam == CRYPT_ERROR )
		{
		*extErrorInfoSet = TRUE;
		if( isGoogle )
			{
			/* We can fingerprint Google Chrome via the braindamage 
			   mentioned above, it also doesn't send a MTI P256 keyex in its 
			   client hello so once we've fallen we can't get up any more */
			retExt( CRYPT_ERROR_NOTAVAIL,
					( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
					  "Google Chrome doesn't support the mandatory P256 "
					  "key exchange in its client handshake, can't "
					  "continue" ) );
			}
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "Couldn't find a supported keyex type in %s's handshake "
				  "message",
				  isServer( sessionInfoPtr ) ? "client" : "server" ) );
		}

	/* If we're fuzzing, we don't do any of the crypto stuff */
	FUZZ_SKIP_REMAINDER();

	/* If we're the server then we now have the parameters that we need to 
	   set up the DH/ECDH crypto */
	if( isServer( sessionInfoPtr ) )
		{
		if( isEccKeyex )
			{
			handshakeInfo->keyexAlgo = CRYPT_ALGO_ECDH;
			status = createDHcontextTLS( &handshakeInfo->dhContext, 
										 CRYPT_ALGO_ECDH );
			if( cryptStatusOK( status ) )
				{
				status = krnlSendMessage( handshakeInfo->dhContext,
										  IMESSAGE_SETATTRIBUTE, &keyexParam,
										  CRYPT_IATTRIBUTE_KEY_ECCPARAM );
				}
			DEBUG_PRINT(( "Keyex set to ECDH, curve ID %d.\n", keyexParam ));
			}
		else
			{
			/* For DH we have to indicate that we're using the nonstandard
			   parameters required by TLS 1.3 */
			keyexParam |= 1;

			handshakeInfo->keyexAlgo = CRYPT_ALGO_DH;
			status = createDHcontextTLS( &handshakeInfo->dhContext, 
										 CRYPT_ALGO_DH );
			if( cryptStatusOK( status ) )
				{
				status = krnlSendMessage( handshakeInfo->dhContext,
										  IMESSAGE_SETATTRIBUTE, &keyexParam,
										  CRYPT_IATTRIBUTE_KEY_DLPPARAM );
				}
			DEBUG_PRINT(( "Keyex set to DH, key size %d.\n", keyexParam ));
			}

		return( status );
		}

	/* We're the client, destroy any contexts from the guessed keyex that 
	   we don't need */
	if( isEccKeyex )
		{
		handshakeInfo->keyexAlgo = CRYPT_ALGO_ECDH;
		if( handshakeInfo->dhContext != CRYPT_ERROR )
			{
			krnlSendNotifier( handshakeInfo->dhContext, 
							  IMESSAGE_DECREFCOUNT );
			}
		handshakeInfo->dhContext = handshakeInfo->dhContextAlt;
		handshakeInfo->dhContextAlt = CRYPT_ERROR;
		DEBUG_PRINT(( "Keyex set to ECDH, curve ID %d.\n", keyexParam ));
		}
	else
		{
		handshakeInfo->keyexAlgo = CRYPT_ALGO_DH;
		if( handshakeInfo->dhContextAlt != CRYPT_ERROR )
			{
			krnlSendNotifier( handshakeInfo->dhContextAlt, 
							  IMESSAGE_DECREFCOUNT );
			handshakeInfo->dhContextAlt = CRYPT_ERROR;
			}
		DEBUG_PRINT(( "Keyex set to DH, key size %d.\n", keyexParam ));
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeKeyexData( INOUT_PTR STREAM *stream,
						   IN_HANDLE const CRYPT_CONTEXT dhContext,
						   IN_ENUM( TLS_GROUP ) \
								const TLS_GROUP_TYPE groupType,
						   IN_LENGTH_SHORT_MIN( 32 ) const int keyDataSize )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( dhContext ) );
	REQUIRES( isEnumRange( groupType, TLS_GROUP ) );
	REQUIRES( isShortIntegerRangeMin( keyDataSize, 32 ) );

	/* Perform Phase 1 of the (EC)DH keyex */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	status = krnlSendMessage( dhContext, IMESSAGE_CTX_ENCRYPT, 
							  &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the group type and keyex data */
	writeUint16( stream, groupType );
	writeUint16( stream, keyDataSize );
	if( isECCGroup( groupType ) )
		{
		/* It's an ECDH keyex value, write it as is */
		status = swrite( stream, keyAgreeParams.publicValue,
						 keyAgreeParams.publicValueLen );
		}
	else
		{
		/* It's a DH keyex value, write it as a fixed-length value */
		status = writeFixedsizeValue( stream, keyAgreeParams.publicValue,
									  keyAgreeParams.publicValueLen, 
									  keyDataSize );
		}

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeKeyexTLS13( INOUT_PTR STREAM *stream,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					 IN_BOOL const BOOLEAN isServer )
	{
	int dhKeySize DUMMY_INIT, dhKeyShareSize = 0;
	int ecdhKeySize DUMMY_INIT, ecdhKeyShareSize = 0;
	int status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBooleanValue( isServer ) );
	REQUIRES( handshakeInfo->dhContext != CRYPT_ERROR || \
			  handshakeInfo->dhContextAlt != CRYPT_ERROR );

	/* Get the key size for each context type.  Because of the unecessary
	   zero-padding requirements we can at least precompute all of the
	   length values without having to actually look at the (EC)DH data */
	if( handshakeInfo->dhContext != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->dhContext, 
								  IMESSAGE_GETATTRIBUTE, &dhKeySize,
								  CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusOK( status ) && \
		handshakeInfo->dhContextAlt != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->dhContextAlt, 
								  IMESSAGE_GETATTRIBUTE, &ecdhKeySize,
								  CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If we're the server then we're just responding to the client's 
	   keyex with a single keyex value.  At this point we'll have been
	   able to sort out whether we're talking DH or ECDH so the values
	   to use in either case are dhContext + dhKeySize */
	if( isServer )
		{
		const int keyexLength = \
			isECCGroup( handshakeInfo->tls13KeyexGroup ) ? \
			1 + dhKeySize + dhKeySize : dhKeySize;
			/* ECC point vs. DH value */

		return( writeKeyexData( stream, handshakeInfo->dhContext, 
								handshakeInfo->tls13KeyexGroup, 
								keyexLength ) );
		}

	/* Calculate the size of the encoded form */
	if( handshakeInfo->dhContext != CRYPT_ERROR )
		dhKeyShareSize = UINT16_SIZE + UINT16_SIZE + dhKeySize;
	if( handshakeInfo->dhContextAlt != CRYPT_ERROR )
		{
		ecdhKeyShareSize = UINT16_SIZE + UINT16_SIZE + 1 + \
						   ecdhKeySize + ecdhKeySize;
		}

	/* We're the client and potentially sending a list of keyex values,
	   write the keyex wrapper */
	writeUint16( stream, dhKeyShareSize + ecdhKeyShareSize );

	/* Write the DH key share */
	if( handshakeInfo->dhContext != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->dhContext, 
								 TLS_GROUP_FFDHE2048, dhKeySize );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the ECDH key share if available */
	if( handshakeInfo->dhContextAlt != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->dhContextAlt, 
								 TLS_GROUP_SECP256R1, 
								 1 + ecdhKeySize + ecdhKeySize );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}
#endif /* USE_TLS13 */
