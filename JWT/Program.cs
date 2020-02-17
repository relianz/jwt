/*
	The MIT License

	Copyright 2020, Dr.-Ing. Markus A. Stulle, München (markus@stulle.zone)

	Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
	and associated documentation files (the "Software"), to deal in the Software without restriction, 
	including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
	and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
	subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all copies 
	or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
	INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
	IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
	WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
	OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace Relianz.Crypto
{
	using static System.Console;
	using static System.Convert;

	using System;									// DateTime, Convert, Base64FormattingOptions, Environment
	using System.IO;								// File
	using System.Text;                              // StringBuilder
	using System.Reflection;                        // MethodBase
	using System.Collections.Generic;				// IEnumerable
	using System.Security.Cryptography;				// RSACryptoServiceProvider, SHA256
	using System.Security.Claims;					// ClaimsIdentity, Claim
	using System.IdentityModel.Tokens.Jwt;			// JwtSecurityTokenHandler

	using Microsoft.IdentityModel.Tokens;			// SecurityTokenDescriptor, SigningCredentials, SymmetricSecurityKey

	using Org.BouncyCastle.Security;				// DotNetUtilities
	using Org.BouncyCastle.OpenSsl;					// PemReader
	using Org.BouncyCastle.Crypto;					// AsymmetricCipherKeyPair
	using Org.BouncyCastle.Crypto.Parameters;       // RsaPrivateCrtKeyParameters

	public class JwtExplorations
	{
        #region public
        public static void Main()
		{
			int loop = 0;
			bool userAborted = false;
			while( !userAborted )
			{
				loop++;
				WriteLine( $"\n[{loop}] Query current configuration..." );
				QueryConfiguration();

				// Feature enabled?
				if ( compareSHA256Implementations )
				{
					string source;

					// Compare SHA-256 implementations from .NET Core and in source:
					source = "";
					CompareSha256Implementations( source );

					source = "IoT Capability - on the leading edge of technology!";
					CompareSha256Implementations( source );

				} // compareSHA256Implementations.

				RsaSecurityKey rsaKey = null;

				// Feature enabled?
				if( generateKeyPair )
				{
					// Create RSA key:
					int keySize = 2048;
					rsaKey = GenerateRsaCryptoServiceProviderKey( keySize );

					// Dump RSA public key in different formats:
					const string path = @"C:\Users\mstulle\source\repos\jwt\testbed\200127_RSA_PubKey.txt";
					DumpRsaPublicKey4Python( rsaKey, path );
					DumpRsaPublicKey( rsaKey );
				}
				else
				{
					// Create RSA key from private key file:
					rsaKey = SecurityKeyFromPemFile( assetPrivateKeyFilePath );
				}

				// Feature enabled?
				if( dumpRsaPrivateKey )
				{
					// Show private part of RSA key pair.
					// Never do that in real world applications!
					DumpRsaPrivateKey( rsaKey );
				}

				// Specify JWT to be signed with private key:
				var now = DateTime.UtcNow;
				var tokenDescriptor = new SecurityTokenDescriptor
				{
					Subject = new ClaimsIdentity( new[]
					{
						new Claim( "email", "markus@stulle.zone" )
					}),

					Expires = now.AddMinutes( 60 ),
					SigningCredentials = new SigningCredentials( rsaKey, SecurityAlgorithms.RsaSha256 )
				};

				// Generate JWT using framework class:
				var tokenHandler = new JwtSecurityTokenHandler();
				var token = tokenHandler.CreateToken( tokenDescriptor );
				var tokenString = tokenHandler.WriteToken( token );

				WriteLine( "\nJWT: {0}", tokenString );

				// Validate JWT:
				JwtSecurityToken validatedToken = ValidateJwt( tokenString, new List<SecurityKey> { rsaKey } );
				string payload = validatedToken.Payload.SerializeToJson().ToString();
				WriteLine( "\nJWT is valid, payload: {0}", payload );

				// Retry?
				WriteLine( "Press <Esc> to abort or <Return> to retry!" );

				// Prevent program from ending if <CTL+C> is pressed:
				TreatControlCAsInput = true;
				
				ConsoleKeyInfo cki = ReadKey();
				if (cki.Key == ConsoleKey.Enter)
					userAborted = false;
				else
				if( cki.Key == ConsoleKey.Escape )
					userAborted = true;
				
			} // while.

		} // Main.
        #endregion

        #region private
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
			string pubKeyString = ToBase64String( pubKeyBytes, 0, pubKeyBytes.Length, Base64FormattingOptions.InsertLineBreaks );

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

		private static RsaSecurityKey SecurityKeyFromPemFile( String filePath )
		{
			// Employ text reader to read PEM file content:
			using( TextReader privateKeyTextReader = new StringReader( File.ReadAllText( filePath ) ) )
			{
				// Create PEM content processor from Bouncy Castle:
				PemReader pr = new PemReader( privateKeyTextReader );

				// Read private part of asymmetric key from file:
				AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();

				// Construct RSA parameters using private key data:
				RSAParameters rsaParams = DotNetUtilities.ToRSAParameters( (RsaPrivateCrtKeyParameters)keyPair.Private );

				// Feed RSA cyrptographic provider with parameters:
				RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
				csp.ImportParameters( rsaParams );

				// Access private key part from provider:
				RsaSecurityKey key = new RsaSecurityKey( csp );

				return key;

			} // using TextReader instance.

		} // SecurityKeyFromPemFile.

		private static void CompareSha256Implementations( string source )
		{
			WriteLine( $"\nSource string to be SHA-256 hashed: <{source}>" );

			string hashA; 
			string hashB;

			// Compute hash using .NET Core implemenatation:
			using( SHA256 sha256Hash = SHA256.Create() )
			{
				hashA = GetHash( sha256Hash, source );
				WriteLine( $"The .NET Core SHA256 class hash is: <{hashA}>" );
			}

			// Compute hash using in source implemenatation:
			hashB = Sha2.GetHash( source );
			WriteLine( $"The in source implemented hash is:  <{hashB}>" );

		} // CompareSha256Implementations.

		private static string GetHash( HashAlgorithm hashAlgorithm, string input )
		{

			// Convert the input string to a byte array and compute the hash:
			byte[] data = hashAlgorithm.ComputeHash( Encoding.UTF8.GetBytes( input ) );

			// Create a new Stringbuilder to collect the bytes and create a string:
			var sBuilder = new StringBuilder();

			// Loop through each byte of the hashed data and format each one as a hexadecimal string:
			for( int i = 0; i < data.Length; i++ )
			{
				sBuilder.Append( data[i].ToString( "X2" ) );
			}

			// Return the hexadecimal string:
			return sBuilder.ToString();

		} // GetHash.

		private static void QueryConfiguration()
		{
			// Access cloud driven configuration provider:
			string envVar = "AzureAppConfiguration_ConnectionString";
			string featureSet = MethodBase.GetCurrentMethod().DeclaringType.Name;

			Features features = Features.GetInstance( envVar, featureSet );
			if( features != null )
			{
				compareSHA256Implementations = features.GetFeatureFlag( "CompareSHA256Implementations" );
				generateKeyPair = features.GetFeatureFlag( "GenerateKeyPair" );
				dumpRsaPrivateKey = features.GetFeatureFlag( "DumpRsaPrivateKey" );

				assetPrivateKeyFilePath = features.GetConfigurationSetting( "AssetPrivateKeyFilePath" );
			}
			else
			{
				WriteLine( $"Cannot query feature set <{featureSet}>" );
				WriteLine( $"Assuming default configuration - Press any key!" );

				compareSHA256Implementations = true;
				generateKeyPair = false;

				ReadLine();

			} // configuration service accessible.

			// Assert valid configuration:
			if( assetPrivateKeyFilePath == null )
			{
				string machine = Environment.MachineName;
				if( machine.Equals( "SANTACLARA" ) )
					assetPrivateKeyFilePath = @"E:\temp\200131 C2 Testbed\200201 asset private key.txt";
				else
					assetPrivateKeyFilePath = @"C:\Users\mstulle\Documents\00 Deloitte\200131 C2 Testbed\200201 asset private key.txt";

			} // assetPrivateKeyFilePath == null

		} // QueryConfiguration

		// Feature flags:
		private static bool compareSHA256Implementations = false;
		private static bool generateKeyPair = false;
		private static bool dumpRsaPrivateKey = false;

		// Additional configuration settings: 
		private static string assetPrivateKeyFilePath = null;

		#endregion

	} // class JwtExplorations.

} // namespace Relianz.Crypto.