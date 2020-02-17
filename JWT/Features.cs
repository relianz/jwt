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

    using System;                                                       // Environment, TimeSpan
    using System.Threading.Tasks;                                       // Task

    using Microsoft.Extensions.Configuration;                           // IConfiguration
    using Microsoft.Extensions.Configuration.AzureAppConfiguration;     // IConfigurationRefresher

    public class Features
    {
		#region public

		// Factory method for querying singleton:
		public static Features GetInstance( string configurationServiceConnectionStringEnvVar, string featureSet )
		{
			// Use double-checked locking to ensure thread safety:
			if( uniqueInstance == null )
			{
				string envVarValue = Environment.GetEnvironmentVariable( configurationServiceConnectionStringEnvVar );
				if( envVarValue == null )
				{
					WriteLine( $"Empty environment variable: <{configurationServiceConnectionStringEnvVar}>" );
				}
				else
				{
					Object lockThis = new Object();
					lock( lockThis )
					{
						uniqueInstance = new Features( envVarValue, featureSet );

					} // lock
				}

			} // must create first instance. 
			else
			{
				// Singleton exists, refresh local configuration cache contents:
				Task.Run( () => _refresher.Refresh() );
			}

			return uniqueInstance;

		} // GetInstance.

		// Query boolean feature flag:
		public bool GetFeatureFlag( string featureFlagName )
		{
			string configKey = featureSet + ":Settings:" + featureFlagName;
			string configValue = _configuration[ configKey ];

			if( configValue == null || configValue.Length == 0 )
			{
				WriteLine( $"Found null or zero length value for key <{configKey}>!" );
				return false;
			}

			bool flag;
			try
			{
				flag = bool.Parse( configValue );
			}
			catch( FormatException fx )
			{
				WriteLine( $"Cannot convert config value <{configValue}> of config key <{configKey}> to boolean value!" );
				return false;
			}

			return flag;

		} // GetFeatureFlag.

		public string GetConfigurationSetting( string configurationSettingName )
		{
			string configKey = featureSet + ":Settings:" + configurationSettingName;
			string configValue = _configuration[ configKey ];

			if( configValue == null )
			{
				WriteLine( $"Found null or zero length value for key <{configKey}>!" );
			}

			return configValue;

		} // GetConfigurationSetting.

		public string FeatureSet { get => featureSet; }
		public string ConnectionString { get => connectionString; }

		#endregion

		#region private

		// Construct singleton instance:
		private Features( string connectionString, string featureSet ) 
		{
			Features.connectionString = connectionString;
			Features.featureSet = featureSet;

			var builder = new ConfigurationBuilder();
			
			builder.AddAzureAppConfiguration( options =>
			{
				options.Connect( connectionString )
						.ConfigureRefresh( refresh =>
						{
							refresh.Register( featureSet + ":Settings:" + "CompareSHA256Implementations" )
								   .SetCacheExpiration( TimeSpan.FromSeconds( secondsConfigCacheExpiration ) );

							refresh.Register( featureSet + ":Settings:" + "GenerateKeyPair" )
								   .SetCacheExpiration( TimeSpan.FromSeconds( secondsConfigCacheExpiration ) );

							refresh.Register( featureSet + ":Settings:" + "DumpRsaPrivateKey" )
								   .SetCacheExpiration( TimeSpan.FromSeconds( secondsConfigCacheExpiration ) );

							refresh.Register( featureSet + ":Settings:" + "AssetPrivateKeyFilePath" )
								   .SetCacheExpiration( TimeSpan.FromSeconds( secondsConfigCacheExpiration ) );
						});

				_refresher = options.GetRefresher();
			});

			_configuration = builder.Build();

			bool checkConcurrentUpdate = false;
			if( checkConcurrentUpdate )
				PrintFeature().Wait();

		} // ctor.

		private static async Task PrintFeature()
		{
			WriteLine( _configuration[ featureSet + ":Settings:CompareSHA256Implementations" ] ?? "No value for CompareSHA256Implementations" );

			// Wait for the user to press Enter
			WriteLine( "Press any key!" );
			ReadLine();

			await _refresher.Refresh();
			WriteLine( _configuration[ featureSet + ":Settings:CompareSHA256Implementations" ] ?? "No value for CompareSHA256Implementations" );

		} // PrintFeature.

		// Overrite default value of 30 seconds:
		private static int secondsConfigCacheExpiration = 5;

		private static string featureSet;
		private static string connectionString;
		private static Features uniqueInstance;

		private static IConfiguration _configuration = null;
		private static IConfigurationRefresher _refresher = null;

		#endregion

	} // class Features.

} // namespace Relianz.Crypto.
