using static System.Console;
using static System.Convert;

using System;                           // DateTime, Convert, Base64FormattingOptions, Environment
using System.IO;                        // File
using System.Text;                      // StringBuilder
using System.Collections.Generic;       // IEnumerable
using System.Security.Cryptography;     // RSACryptoServiceProvider
using System.Security.Claims;           // ClaimsIdentity, Claim
using System.IdentityModel.Tokens.Jwt;	// JwtSecurityTokenHandler
using Microsoft.IdentityModel.Tokens;   // SecurityTokenDescriptor, SigningCredentials, SymmetricSecurityKey

public class Program
{
	public static void Main()
	{
		var tokenHandler = new JwtSecurityTokenHandler();
		var now = DateTime.UtcNow;

		// Create RSA key:
		const int keySize = 2048;
		RsaSecurityKey rsaKey = GenerateRsaCryptoServiceProviderKey( keySize );

		// Dump RSA key parts:
		const string path = @"C:\Users\mstulle\source\repos\jwt\testbed\200127_RSA_PubKey.txt";
		DumpRsaPublicKey( rsaKey, path );
		DumpRsaPrivateKey( rsaKey );

		// Specify JWT:
		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity( new[]
			{
				new Claim( "email", "mstulle@deloitte.de" )
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

	static private void DumpRsaPublicKey( RsaSecurityKey key, string filePath )
	{
		const string pemPubKeyBegin = @"-----BEGIN PUBLIC KEY-----\n";
		const string pemPubKeyEnd = @"\n-----END PUBLIC KEY-----\n";

		byte[] pubKeyBytes = key.Rsa.ExportRSAPublicKey();
		string pubKeyString = ToBase64String( pubKeyBytes, 0, pubKeyBytes.Length, Base64FormattingOptions.InsertLineBreaks );

		StringBuilder builder = new StringBuilder();
		builder.Append( pemPubKeyBegin ).Append( pubKeyString ).Append( pemPubKeyEnd );
		string s = builder.ToString().Replace( "\r\n", @"\n" );

		// Create/overwrite public key file:
		File.WriteAllText( filePath, s );
		
		WriteLine( "\nPublic key:\n{0}", s );

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

} // class Program. 