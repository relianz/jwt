using static System.Console;
using static System.Convert;

using System;                               // DateTime, Convert, Base64FormattingOptions, Environment
using System.IO;                            // File
using System.Text;                          // StringBuilder
using System.Collections.Generic;           // IEnumerable
using System.Security.Cryptography;         // RSACryptoServiceProvider
using System.Security.Claims;               // ClaimsIdentity, Claim
using System.IdentityModel.Tokens.Jwt;      // JwtSecurityTokenHandler
using Microsoft.IdentityModel.Tokens;       // SecurityTokenDescriptor, SigningCredentials, SymmetricSecurityKey

using Org.BouncyCastle.Security;            // DotNetUtilities
using Org.BouncyCastle.OpenSsl;             // PemReader
using Org.BouncyCastle.Crypto;              // AsymmetricCipherKeyPair
using Org.BouncyCastle.Crypto.Parameters;   // RsaPrivateCrtKeyParameters

public class Program
{
	public static void Main()
	{
		var tokenHandler = new JwtSecurityTokenHandler();
		var now = DateTime.UtcNow;

		const bool generateKeyPair = false;
		RsaSecurityKey rsaKey = null;

		if ( generateKeyPair )
		{
			// Create RSA key:
			const int keySize = 2048;
			rsaKey = GenerateRsaCryptoServiceProviderKey( keySize );

			// Dump RSA key parts:
			const string path = @"C:\Users\mstulle\source\repos\jwt\testbed\200127_RSA_PubKey.txt";
			DumpRsaPublicKey4Python(rsaKey, path);
			DumpRsaPublicKey(rsaKey);
		}
		else
		{
			// Create RSA key from private key file:
			const string assetKeyPath = @"C:\Users\mstulle\Documents\00 Deloitte\200131 C2 Testbed\200201 asset private key.txt";
			rsaKey = SecurityKeyFromPemFile( assetKeyPath );
		}

		// Show private part of RSA key pair:
		DumpRsaPrivateKey( rsaKey );

		// Specify JWT:
		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity( new[]
			{
				new Claim( "email", "markus@stulle.zone" )
			}),
			Expires = now.AddMinutes( 60 ),
			SigningCredentials = new SigningCredentials( rsaKey, SecurityAlgorithms.RsaSha256 ),
		};

		// Generate JWT:
		var token = tokenHandler.CreateToken( tokenDescriptor );
		var tokenString = tokenHandler.WriteToken( token );

		WriteLine( "\nJWT: {0}", tokenString );

		// Validate JWT:
		JwtSecurityToken validatedToken = ValidateJwt( tokenString, new List<SecurityKey> { rsaKey } );
		string payload = validatedToken.Payload.SerializeToJson().ToString();
		WriteLine( "\nJWT is valid, payload: {0}", payload );

	} // Main.

	static private RsaSecurityKey GenerateRsaCryptoServiceProviderKey( int dwKeySize )
	{
		var rsaProvider = new RSACryptoServiceProvider( dwKeySize );
		RsaSecurityKey key = new RsaSecurityKey( rsaProvider );

		return key;

	} // GenerateRsaCryptoServiceProviderKey.

	static private void DumpRsaPublicKey4Python( RsaSecurityKey key, string filePath )
	{
		const string pemPubKeyBegin = @"-----BEGIN PUBLIC KEY-----\n";
		const string pemPubKeyEnd = @"\n-----END PUBLIC KEY-----";

		byte[] pubKeyBytes = key.Rsa.ExportRSAPublicKey();
		string pubKeyString = ToBase64String( pubKeyBytes, 0, pubKeyBytes.Length, Base64FormattingOptions.InsertLineBreaks );

		StringBuilder builder = new StringBuilder();
		builder.Append( pemPubKeyBegin ).Append( pubKeyString ).Append( pemPubKeyEnd );
		string s = builder.ToString().Replace( "\r\n", @"\n" );

		// Create/overwrite public key file:
		File.WriteAllText( filePath, s );
		
		WriteLine( "\nPublic key, Python format:\n{0}", s );

	} // DumpRsaPublicKey4Python.

	static private void DumpRsaPublicKey(RsaSecurityKey key)
	{
		const string pemPubKeyBegin = "-----BEGIN PUBLIC KEY-----\n";
		const string pemPubKeyEnd = "\n-----END PUBLIC KEY-----";

		byte[] pubKeyBytes = key.Rsa.ExportRSAPublicKey();
		string pubKeyString = ToBase64String(pubKeyBytes, 0, pubKeyBytes.Length, Base64FormattingOptions.InsertLineBreaks);

		StringBuilder builder = new StringBuilder();
		builder.Append(pemPubKeyBegin).Append(pubKeyString).Append(pemPubKeyEnd);
		
		WriteLine( "\nPublic key:\n{0}", builder.ToString()	);

	} // DumpRsaPublicKey.

	static private void DumpRsaPrivateKey( RsaSecurityKey key )
	{
		byte[] privKeyBytes = key.Rsa.ExportRSAPrivateKey();
		string privKeyString = ToBase64String( privKeyBytes, 0, privKeyBytes.Length, Base64FormattingOptions.None );
		
		WriteLine( "\nPrivate key:\n{0}", privKeyString );

	} // DumpRsaPrivateKey.

	private static JwtSecurityToken ValidateJwt( string jwt, IEnumerable<SecurityKey> signingKeys )
	{
		var validationParameters = new TokenValidationParameters
		{
			// Clock skew compensates for server time drift.
			// We recommend 5 minutes or less:
			ClockSkew = TimeSpan.FromMinutes( 5 ),
			
			// Specify the key used to sign the token:
			IssuerSigningKeys = signingKeys,
			RequireSignedTokens = true,
			
			// Ensure the token hasn't expired:
			RequireExpirationTime = true,
			ValidateLifetime = true,
			
			// Ensure the token audience matches our audience value (default true):
			ValidateAudience = false,
			ValidAudience = "api://default",

			// Ensure the token was issued by a trusted authorization server (default true):
			ValidateIssuer = false			
		};

		var tokenHandler = new JwtSecurityTokenHandler();

		try
		{
			var claimsPrincipal = tokenHandler.ValidateToken( jwt, validationParameters, out var rawValidatedJwt );

			return (JwtSecurityToken)rawValidatedJwt;
			// Or, you can return the ClaimsPrincipal
			// (which has the JWT properties automatically mapped to .NET claims)
		}
		catch( SecurityTokenValidationException stvex )
		{
			// The token failed validation!
			// TODO: Log it or display an error.
			throw new Exception( $"Token failed validation: {stvex.Message}" );
		}
		catch( ArgumentException argex )
		{
			// The token was not well-formed or was invalid for some other reason.
			// TODO: Log it or display an error.
			throw new Exception( $"Token was invalid: {argex.Message}" );
		}

	} // ValidateJwt.

	public static RsaSecurityKey SecurityKeyFromPemFile( String filePath )
	{
		using (TextReader privateKeyTextReader = new StringReader( File.ReadAllText( filePath ) ) )
		{
			PemReader pr = new PemReader( privateKeyTextReader );
			AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
			RSAParameters rsaParams = DotNetUtilities.ToRSAParameters( (RsaPrivateCrtKeyParameters)keyPair.Private );

			RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
			csp.ImportParameters( rsaParams );
			RsaSecurityKey key = new RsaSecurityKey( csp );

			return key;

		} // using TextReader instance.

	} // SecurityKeyFromPemFile.

} // class Program. 