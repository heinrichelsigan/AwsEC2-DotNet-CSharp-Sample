using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Text;

namespace AwsEC2Sample1
{
    internal static class AWSConfigSettings
    {
        const string PROTO = "https://";
        const string DOMAIN = "amazonaws.com";
        const char DOT = '.';

        /// <summary>
        /// PowerShell script for creating S3 bucket and allowing write access to it
        /// </summary>
        internal const string POWERSHELL_S3_BUCKET_SCRIPT =
             "<powershell>\n" +
                "Import-Module \"C:\\Program Files (x86)\\AWS Tools\\PowerShell\\AWSPowerShell\\AWSPowerShell.psd1\"\n" +
                "Set-DefaultAWSRegion {0}\n" +
                "New-Item C:\\Windows\\Temp -type directory\n" +
                "Add-Content -path C:\\Windows\\Temp\\s3-bucket-results.txt -value \"Results from lots of data processing\"\n" +
                "New-S3Bucket -BucketName {1}\n" +
                "Write-S3Object -BucketName {1} -File C:\\Windows\\Temp\\s3-bucket-results.txt -Key results.txt\n" +
                "shutdown.exe /s\n" +
            "</powershell>";
       
        /// <summary>
        /// Gets AWSAppSettings from Configuration
        /// </summary>
        internal static NameValueCollection AWSAppSettings
        {
            get {
                return System.Configuration.ConfigurationManager.AppSettings;
            }
        }

        /// <summary>
        /// Gets value stored at AWSAppSettings[key] 
        /// </summary>
        /// <param name="key">key string from KeyValuePair of Configuration AppSettings</param>
        /// <returns>value string</returns>
        internal static string AWSConfigGetKey(string key)
        {
            string awsValue = null;
            foreach (var nextKey in AWSConfigSettings.AWSAppSettings.Keys)
            {
                if (nextKey.ToString() == key)
                {
                    awsValue = AWSConfigSettings.AWSAppSettings.Get(key);
                    if (!string.IsNullOrEmpty(awsValue))
                    {
                        return awsValue;
                    }
                    throw new ConfigurationErrorsException(
                        String.Format("AWSConfigSettings.AWSAppSettings[\"{0}\"] returns null or void Value", key),
                        new NullReferenceException(String.Format("AWSConfigSettings.AWSAppSettings[\"{0}\"] is \'\\0\' || \"\"", key))
                    );
                }
            }

            throw new ConfigurationErrorsException(
                String.Format("AWSConfigSettings.AWSAppSettings[\"{0}\"] contains no key {1} not found inside <configuration>[...]<appSettings>[...]", key, key),
                new NullReferenceException(String.Format("AWSConfigSettings.AWSAppSettings[\"{0}\"] is \'\\0\' (null)", key))
                );
        }

        /// <summary>
        /// Gets AWSProfileName from ConfigSettings
        /// </summary>
        public static string AWSProfileName
        {
            get {
                return AWSConfigSettings.AWSConfigGetKey("AWSProfileName");
            }
        }

        /// <summary>
        /// Gets AWSRegion from ConfigSettings
        /// </summary>
        public static string AWSRegion
        {
            get
            {
                string region = "eu-west-1";
                try
                {
                    region = AWSConfigSettings.AWSConfigGetKey("AWSRegion");
                }
                catch (Exception)
                {
                    region = "eu-west-1";
                }
                return region;
            }
        }

        /// <summary>
        /// Gets Amazon.RegionEndpoint from ConfigSettings
        /// </summary>
        public static Amazon.RegionEndpoint AWSRegionEndpoint 
        {
            get {
                string compareRegion = AWSConfigSettings.AWSRegion.Replace("_", string.Empty).ToLower();
                foreach (Amazon.RegionEndpoint endpoint in Amazon.RegionEndpoint.EnumerableAllRegions)
                {
                    if ((endpoint.DisplayName.ToLower() == AWSConfigSettings.AWSRegion.Replace("_", string.Empty).ToLower()) ||
                        (endpoint.SystemName.ToLower() == AWSConfigSettings.AWSRegion.Replace("_", string.Empty).ToLower()) ||
                        (endpoint.ToString().ToLower() == AWSConfigSettings.AWSRegion.Replace("_", string.Empty).ToLower()))
                    {
                        return endpoint;
                    }
                }
                return Amazon.RegionEndpoint.EUWest1;
            }
        }

        /// <summary>
        /// Gets AWSServiceUrl from ConfigSettings
        /// </summary>
        public static String AWSServiceUrl
        {
            get {
                string serviceUrl = String.Concat(
                    PROTO.ToString(),
                    AWSConfigSettings.AWSRegion,
                    ((DOMAIN[0] != DOT) ? DOT.ToString() : string.Empty),
                    DOMAIN.ToString()
                    );
                return serviceUrl;
            }
        }

        /// <summary>
        /// Gets AWSServiceUri from ConfigSettings
        /// </summary>
        public static Uri AWSServiceUri
        {
            get {
                return (new Uri(AWSConfigSettings.AWSServiceUrl, UriKind.Absolute));
            }
        }

        /// <summary>
        /// Gets S3BucketName from Configuration
        /// </summary>
        public static string S3BucketName
        {
            get
            {
                return AWSConfigSettings.AWSConfigGetKey("S3BucketName");
            }

        }

        /// <summary>
        /// Gets AWSAccessKey from Configuration
        /// </summary>
        public static string AWSAccessKey
        {
            get {
                return AWSConfigSettings.AWSConfigGetKey("AWSAccessKey");
            }
        }

        /// <summary>
        /// Gets AWSSecretKey from Configuration
        /// </summary>
        public static string AWSSecretKey
        {
            get
            {
                return AWSConfigSettings.AWSConfigGetKey("AWSSecretKey");
            }
        }


    }
}
