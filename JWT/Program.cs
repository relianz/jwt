using static System.Console;
using System.Text;						// Encoding
using System.Security.Claims;           // ClaimsIdentity, Claim
using System.Security.Cryptography;		// RSACryptoServiceProvider
using System.IdentityModel.Tokens.Jwt;	// JwtSecurityTokenHandler
using Microsoft.IdentityModel.Tokens;   // SecurityTokenDescriptor, SigningCredentials, SymmetricSecurityKey

public class Program
{
	public static void Main()
	{
		var tokenHandler = new JwtSecurityTokenHandler();
		var now = System.DateTime.UtcNow;

		/*
		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(new[]
			{
				new Claim( "email", "test@test.com" ),
				new Claim( "firstName", "test" ),
				new Claim( "lastName", "test" )
			}),
			Expires = now.AddMinutes(3),
			SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretsecretsecret")), SecurityAlgorithms.HmacSha256),
		};
		*/

		SecurityKey rsaKey = GenerateRsaCryptoServiceProviderKey();
		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(new[]
			{
				new Claim( "email", "mstulle@deloitte.de" )
			}),
			Expires = now.AddMinutes(3),
			SigningCredentials = new SigningCredentials( rsaKey, SecurityAlgorithms.RsaSha256 ),
		};

		var token = tokenHandler.CreateToken(tokenDescriptor);

		var tokenString = tokenHandler.WriteToken(token);

		WriteLine(tokenString);
	}

	static private SecurityKey GenerateRsaCryptoServiceProviderKey()
	{
		var rsaProvider = new System.Security.Cryptography.RSACryptoServiceProvider(2048);
		SecurityKey key = new RsaSecurityKey( rsaProvider );

		return key;
	}
}