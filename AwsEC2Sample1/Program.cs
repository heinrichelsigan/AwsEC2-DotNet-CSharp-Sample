/*******************************************************************************
* Copyright 2009-2013 Amazon.com, Inc. or its affiliates. All Rights Reserved.
* 
* Licensed under the Apache License, Version 2.0 (the "License"). You may
* not use this file except in compliance with the License. A copy of the
* License is located at
* 
* http://aws.amazon.com/apache2.0/
* 
* or in the "license" file accompanying this file. This file is
* distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied. See the License for the specific
* language governing permissions and limitations under the License.
*******************************************************************************/

using System;
using System.Collections.Generic;
using System.Threading;

using Amazon;
using Amazon.EC2;
using Amazon.EC2.Model;
using Amazon.EC2.Util;

using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;

using Amazon.Auth.AccessControlPolicy;
using Amazon.Auth.AccessControlPolicy.ActionIdentifiers;

using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Util;
using System.IO;

namespace AwsEC2Sample1
{
    /// <summary>
    /// This sample shows how to launch an Amazon EC2 instance with a PowerShell script that is executed when the 
    /// instance becomes available and access Amazon S3.
    /// </summary>
    class Program
    {       

        static readonly string RESOURCDE_POSTFIX = DateTime.Now.Ticks.ToString();
        static readonly string SAMPLE_PREFIX = AWSConfigSettings.AWSSamplePrefix;
        static readonly string SAMPLE_NAME = SAMPLE_PREFIX +
            DateTime.Now.ToShortDateString() + "_" + DateTime.Now.ToShortTimeString().Replace(":", ".");
        static readonly string SAMPLE_LONG_UNIQUE_NAME = SAMPLE_PREFIX + RESOURCDE_POSTFIX;
        const bool CREATE_AND_SAVE_KEY_PAIR = true;


        public static void Main(string[] args)
        {

            string awsProfileName = AWSConfigSettings.AWSProfileName;

            AmazonEC2Config config = new AmazonEC2Config();
            config.ServiceURL = AWSConfigSettings.AWSServiceUrl;
            Amazon.Runtime.AWSCredentials credentials = new Amazon.Runtime.StoredProfileAWSCredentials(awsProfileName);
            // AmazonEC2Client ec2Client = new AmazonEC2Client(credentials, config);
            AmazonEC2Client ec2Client = new AmazonEC2Client();

            var bucketName = SAMPLE_LONG_UNIQUE_NAME;            

            // Get latest 2012 Base AMI
            var imageId = ImageUtilities.FindImage(ec2Client, ImageUtilities.WINDOWS_2012_BASE).ImageId;
            Console.WriteLine("Using Image ID: {0}", imageId);

            // Create an IAM role
            var instanceProfileArn = CreateInstanceProfile();
            Console.WriteLine("Created Instance Profile: {0}", instanceProfileArn);

            Thread.Sleep(15000);

            // Check existing keypairs
            string keyPairName = SAMPLE_LONG_UNIQUE_NAME;

            var dkpRequest = new DescribeKeyPairsRequest();
            var dkpResponse = ec2Client.DescribeKeyPairs(dkpRequest);
            List<KeyPairInfo> myKeyPairs = dkpResponse.KeyPairs;
            foreach (KeyPairInfo item in myKeyPairs)
            {
                Console.WriteLine("Existing key pair: " + item.KeyName);
            }

            // Create new KeyPair
            KeyPair newKeyPair = null;
            CreateKeyPairRequest newKeyRequest = new CreateKeyPairRequest() { KeyName = keyPairName };
            CreateKeyPairResponse ckpResponse = ec2Client.CreateKeyPair(newKeyRequest);
            // store the received new Key   
            newKeyPair = ckpResponse.KeyPair;
            Console.WriteLine();
            Console.WriteLine("New key: " + keyPairName);
            Console.WriteLine("fingerprint: " + newKeyPair.KeyFingerprint);
            Console.WriteLine();
            // Save the private key in a .pem file
            using (FileStream s = new FileStream(keyPairName + ".pem", FileMode.Create))
            {
                using (StreamWriter writer = new StreamWriter(s))
                {
                    writer.WriteLine(newKeyPair.KeyMaterial);
                    Console.WriteLine(newKeyPair.KeyMaterial);
                }
            }

            string secGroupId = string.Empty;
            // Create new security Group 
            try
            {
                System.Net.HttpStatusCode createSecGrCode = CreateSecurityGroup(ec2Client, ref secGroupId);
            }
            catch (AmazonEC2Exception ae)
            {
                if (string.Equals(ae.ErrorCode, "InvalidGroup.Duplicate", StringComparison.InvariantCulture))
                    Console.WriteLine(ae.Message);
                else throw;
            }

            // add ip ranges
            String ipSource = "0.0.0.0/0";
            List<String> ipRanges = new List<String>();
            ipRanges.Add(ipSource);

            List<IpPermission> ipPermissions = new List<IpPermission>();
            IpPermission tcpSSH = new IpPermission() { IpProtocol = "tcp", FromPort = 22, ToPort = 22, IpRanges = ipRanges };
            ipPermissions.Add(tcpSSH);
            IpPermission tcpHTTP = new IpPermission() { IpProtocol = "tcp", FromPort = 80, ToPort = 80, IpRanges = ipRanges };
            ipPermissions.Add(tcpHTTP);
            IpPermission tcpHTTPS = new IpPermission() { IpProtocol = "tcp", FromPort = 443, ToPort = 443, IpRanges = ipRanges };
            ipPermissions.Add(tcpHTTPS);
            IpPermission tcpMYSQL = new IpPermission() { IpProtocol = "tcp", FromPort = 3306, ToPort = 3306, IpRanges = ipRanges };
            ipPermissions.Add(tcpMYSQL);
            IpPermission tcpRDP = new IpPermission() { IpProtocol = "tcp", FromPort = 3389, ToPort = 3389, IpRanges = ipRanges };
            ipPermissions.Add(tcpRDP);

            try
            {
                // Authorize the ports to be used.

                AuthorizeSecurityGroupIngressRequest ipPermissionsRequest = new AuthorizeSecurityGroupIngressRequest();
                ipPermissionsRequest.IpPermissions = ipPermissions;
                ipPermissionsRequest.GroupName = SAMPLE_NAME;
                if (!string.IsNullOrEmpty(secGroupId)) {
                    ipPermissionsRequest.GroupId = secGroupId;
                }
                AuthorizeSecurityGroupIngressResponse authResp = ec2Client.AuthorizeSecurityGroupIngress(ipPermissionsRequest);
                
                Console.WriteLine("Auth SecurityGroup Request HttpStatusCode " + authResp.HttpStatusCode + " ");
                Console.WriteLine(authResp.ResponseMetadata);
            }
            catch (AmazonEC2Exception ae)
            {
                if (String.Equals(ae.ErrorCode, "InvalidPermission.Duplicate", StringComparison.InvariantCulture))
                    Console.WriteLine(ae.Message);
                else
                    throw;
            }

            // run ec2 instance request with existing or new generated keypair
            var runRequest = new RunInstancesRequest
            {
                ImageId = imageId,
                MinCount = 1,
                MaxCount = 1,
                KeyName = newKeyPair.KeyName, //keyPair.KeyName,
                IamInstanceProfile = new IamInstanceProfileSpecification { Arn = instanceProfileArn },                            
                    
                // Add the region for the S3 bucket and the name of the bucket to create
                UserData = EncodeToBase64(
                    string.Format(
                        AWSConfigSettings.POWERSHELL_S3_BUCKET_SCRIPT,
                        AWSConfigSettings.AWSRegionEndpoint.SystemName,
                        bucketName)
                    )
            };

            // add secGroupId
            if (!string.IsNullOrEmpty(secGroupId)) {
                runRequest.SecurityGroupIds.Add(secGroupId);
            }
            
            var instanceId = ec2Client.RunInstances(runRequest).Reservation.Instances[0].InstanceId;
            Console.WriteLine("Launch Instance {0}", instanceId);


            // Create the name tag
            ec2Client.CreateTags(new CreateTagsRequest
            {
                Resources = new List<string> { instanceId },
                Tags = new List<Amazon.EC2.Model.Tag> { new Amazon.EC2.Model.Tag { Key = "Name", Value = "Processor" } }
            });
            Console.WriteLine("Adding Name Tag to instance");

            // create ElastiCache Cluster
            try
            {
                Amazon.ElastiCache.AmazonElastiCacheConfig eCacheConfig = new Amazon.ElastiCache.AmazonElastiCacheConfig();
                eCacheConfig.ServiceURL = AWSConfigSettings.AWSServiceUrl;
                Amazon.ElastiCache.AmazonElastiCacheClient eCacheClient = new Amazon.ElastiCache.AmazonElastiCacheClient();
                // List<string> x = new List<string>();
                // x.Add(secGroupId);
                // Amazon.ElastiCache.Model.CreateCacheClusterRequest eCacheReq = new Amazon.ElastiCache.Model.CreateCacheClusterRequest(
                //    "cache-cluster" + SAMPLE_NAME, 2, "cache.t2.medium", "memcached", x);
                Amazon.ElastiCache.Model.CreateCacheClusterRequest eCacheReq = new Amazon.ElastiCache.Model.CreateCacheClusterRequest(
                                    "Christian", 2, "cache.t2.medium", "memcached", new List<string>());
                
                Amazon.ElastiCache.Model.CreateCacheClusterResponse eCacheResp = eCacheClient.CreateCacheCluster(eCacheReq);
                Console.WriteLine("Cache Cluster Created" + eCacheResp.HttpStatusCode.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine();
            }

            // rds client
            Amazon.RDS.AmazonRDSConfig rdsConf = new Amazon.RDS.AmazonRDSConfig();
            rdsConf.ServiceURL = AWSConfigSettings.AWSServiceUrl;
            Amazon.RDS.AmazonRDSClient rdsClient = new Amazon.RDS.AmazonRDSClient();
            
            // create Database Cluster with aurora DB
            string dbClusterIdentifier = string.Empty;
            try
            {
                Amazon.RDS.Model.DBCluster createdCluster = 
                    CreateDBClusterRDS(rdsClient, SAMPLE_NAME, "aurora", "root", SAMPLE_LONG_UNIQUE_NAME, secGroupId, ref dbClusterIdentifier);
                Console.WriteLine("Created DBCluster with Id " + createdCluster.DBClusterIdentifier);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine();
            }

            Console.WriteLine("Waiting for EC2 Instance to stop");
            // The script put in the user data will shutdown the instance when it is complete.  Wait
            // till the instance has stopped which signals the script is done so the instance can be terminated.
            Instance instance = null;
            var instanceDescribeRequest = new DescribeInstancesRequest { InstanceIds = new List<string> { instanceId } };
            do
            {
                Thread.Sleep(10000);
                instance = ec2Client.DescribeInstances(instanceDescribeRequest).Reservations[0].Instances[0];

                if (instance.State.Name == "stopped")
                {
                    // Demonstrate how to get the Administrator password using the keypair.
                    var passwordResponse = ec2Client.GetPasswordData(new GetPasswordDataRequest
                    {
                        InstanceId = instanceId
                    });

                    // Make sure we actually got a password
                    if (passwordResponse.PasswordData != null)
                    {
                        var password = passwordResponse.GetDecryptedPassword(newKeyPair.KeyMaterial);
                        Console.WriteLine("The Windows Administrator password is: {0}", password);
                    }
                }
            } while (instance.State.Name == "pending" || instance.State.Name == "running");


            // Terminate instance
            Console.WriteLine("Terminate Instances " + instanceId.ToString());
            ec2Client.TerminateInstances(new TerminateInstancesRequest
            {
                InstanceIds = new List<string>() { instanceId }
            });

            // Delete key pair created for sample.
            Console.WriteLine("Delete KeyPair " + newKeyPair.KeyName);
            ec2Client.DeleteKeyPair(new DeleteKeyPairRequest { KeyName = newKeyPair.KeyName });
            
            try
            {
                var s3Client = new AmazonS3Client();
                var listResponse = s3Client.ListObjects(new ListObjectsRequest
                {
                    BucketName = bucketName
                });
                if (listResponse.S3Objects.Count > 0)
                {
                    Console.WriteLine("Found results file {0} in S3 bucket {1}", listResponse.S3Objects[0].Key, bucketName);
                }

                // Delete bucket created for sample.
                AmazonS3Util.DeleteS3BucketWithObjects(s3Client, bucketName);
                Console.WriteLine("Deleted S3 bucket created for sample.");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine();
            }

            // delete DB Cluster
            try
            {
                System.Net.HttpStatusCode delClusterStatus = DeleteDBClusterRDS(rdsClient, dbClusterIdentifier);
                Console.WriteLine("Delete Cluster Request with Id " + dbClusterIdentifier + " returned " + delClusterStatus.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine();
            }


            Thread.Sleep(1000); 

            Console.WriteLine("Delete Instance Profile created for sample.");
            DeleteInstanceProfile();

            // delete Security Group

            try
            {
                System.Net.HttpStatusCode delSecGroupStatus = DeleteSecurityGroup(ec2Client, secGroupId);
                Console.WriteLine("Delete SecurityGroup " + secGroupId + " returned " + delSecGroupStatus.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine();
            }


            Console.WriteLine("Instance terminated, push enter to exit the program");
            Console.Read();

        }


        /// <summary>
        /// CreateSecurityGroup
        /// </summary>
        /// <param name="ref ec2Client"></param>
        /// <param name="secGroupId"></param>
        /// <returns></returns>
        static System.Net.HttpStatusCode CreateSecurityGroup(AmazonEC2Client ec2Client, ref string secGroupId)
        {
            CreateSecurityGroupRequest securityGroupRequest = new CreateSecurityGroupRequest();
            securityGroupRequest.GroupName = SAMPLE_NAME;
            securityGroupRequest.Description = SAMPLE_LONG_UNIQUE_NAME;
            CreateSecurityGroupResponse secRes = ec2Client.CreateSecurityGroup(securityGroupRequest);
            Console.WriteLine("Created security Group with GroupId " + secRes.GroupId);

            secGroupId = secRes.GroupId;
            Console.WriteLine(secRes.ResponseMetadata);
            return secRes.HttpStatusCode;
        }

        /// <summary>
        /// CreateDBClusterRDS
        /// </summary>
        /// <param name="rdsClient"></param>
        /// <param name="databaseName"></param>
        /// <param name="databaseEngine"></param>
        /// <param name="MasterUsername"></param>
        /// <param name="MasterUserPassword"></param>
        /// <param name="secGroupId"></param>
        /// <param name="ref dbClusterIdentifier"></param>
        /// <returns></returns>
        static Amazon.RDS.Model.DBCluster CreateDBClusterRDS(Amazon.RDS.AmazonRDSClient rdsClient, 
            string databaseName, 
            string databaseEngine,
            string MasterUsername,
            string MasterUserPassword,
            string secGroupId, ref string dbClusterIdentifier)
        {
            Amazon.RDS.Model.CreateDBClusterRequest createClusterReq = new Amazon.RDS.Model.CreateDBClusterRequest();
            createClusterReq.DatabaseName = databaseName;
            createClusterReq.DBClusterIdentifier = dbClusterIdentifier;
            createClusterReq.Engine = databaseEngine;
            if (!string.IsNullOrEmpty(secGroupId))
            {
                createClusterReq.VpcSecurityGroupIds.Add(secGroupId);
            }
            createClusterReq.MasterUserPassword = MasterUserPassword;
            createClusterReq.MasterUsername = MasterUsername;

            Amazon.RDS.Model.CreateDBClusterResponse createClusterResp = rdsClient.CreateDBCluster(createClusterReq);
            Amazon.RDS.Model.DBCluster createdCluster = createClusterResp.DBCluster;
            dbClusterIdentifier = createdCluster.DBClusterIdentifier;
            return createdCluster;
        }

        /// <summary>
        /// DeleteDBClusterRDS
        /// </summary>
        /// <param name="rdsClient">Amazon.RDS.AmazonRDSClient</param>
        /// <param name="dbClusterIdentifier">Identifier of RDS DatabaseCluster 2 delete</param>
        /// <returns></returns>
        static System.Net.HttpStatusCode DeleteDBClusterRDS(Amazon.RDS.AmazonRDSClient rdsClient, string dbClusterIdentifier)
        {
            if (!string.IsNullOrEmpty(dbClusterIdentifier))
            {
                throw new ArgumentException("Null or Empty DBClusterIdentifier which is needed for Amazon.RDS.Model.DeleteDBClusterRequest", "string dbClusterIdentifier");
            }
            Console.WriteLine("Deleting DeleteDBClusterRDS with identifier " + dbClusterIdentifier);
            Amazon.RDS.Model.DeleteDBClusterRequest delClusterReq = new Amazon.RDS.Model.DeleteDBClusterRequest();
            delClusterReq.DBClusterIdentifier = dbClusterIdentifier;
            Amazon.RDS.Model.DeleteDBClusterResponse delClusterResp = rdsClient.DeleteDBCluster(delClusterReq);
            return delClusterResp.HttpStatusCode;
        }

        /// <summary>
        /// DeleteSecurityGroup
        /// </summary>
        /// <param name="ec2Client">EC2Client</param>
        /// <param name="securityGroupId">Identifier of SecurityGroup 2 delete</param>
        /// <returns>HttpStatusCode</returns>
        static System.Net.HttpStatusCode DeleteSecurityGroup(AmazonEC2Client ec2Client, string securityGroupId)
        {
            if (!string.IsNullOrEmpty(securityGroupId))
            {
                throw new ArgumentException("Null or Empty securityGroupId which is needed for Amazon.EC2.Model.DeleteSecurityGroupRequest", "string securityGroupId");
            }
            Console.WriteLine("Deleting SecurityGroup " + securityGroupId);
            DeleteSecurityGroupRequest delSecGroupReq = new DeleteSecurityGroupRequest();
            delSecGroupReq.GroupId = securityGroupId;
            DeleteSecurityGroupResponse delSecGroupResp = ec2Client.DeleteSecurityGroup(delSecGroupReq);
            return delSecGroupResp.HttpStatusCode;
        }

        /// <summary>
        /// Create instance profile & grant EC2 instance requesting S3 bucket
        /// </summary>
        /// <returns></returns>
        static string CreateInstanceProfile()
        {
            var roleName = SAMPLE_NAME;
            var client = new AmazonIdentityManagementServiceClient();
            client.CreateRole(new CreateRoleRequest
            {
                RoleName = roleName,
                AssumeRolePolicyDocument = @"{""Statement"":[{""Principal"":{""Service"":[""ec2.amazonaws.com""]},""Effect"":""Allow"",""Action"":[""sts:AssumeRole""]}]}"
            });

            var statement = new Amazon.Auth.AccessControlPolicy.Statement(
                Amazon.Auth.AccessControlPolicy.Statement.StatementEffect.Allow);
            statement.Actions.Add(S3ActionIdentifiers.AllS3Actions);
            statement.Resources.Add(new Resource("*"));

            var policy = new Policy();
            policy.Statements.Add(statement);

            client.PutRolePolicy(new PutRolePolicyRequest
            {
                RoleName = roleName,
                PolicyName = "S3Access",
                PolicyDocument = policy.ToJson()
            });

            var response = client.CreateInstanceProfile(new CreateInstanceProfileRequest
            {
                InstanceProfileName = roleName
            });

            client.AddRoleToInstanceProfile(new AddRoleToInstanceProfileRequest
            {
                InstanceProfileName = roleName,
                RoleName = roleName
            });

            return response.InstanceProfile.Arn;
        }

        /// <summary>
        /// Delete the instance profile created for the sample.
        /// </summary>
        static void DeleteInstanceProfile()
        {
            var roleName = SAMPLE_NAME;
            var client = new AmazonIdentityManagementServiceClient();

            client.DeleteRolePolicy(new DeleteRolePolicyRequest
            {
                RoleName = roleName,
                PolicyName = "S3Access"
            });

            client.RemoveRoleFromInstanceProfile(new RemoveRoleFromInstanceProfileRequest
            {
                InstanceProfileName = roleName,
                RoleName = roleName
            });

            client.DeleteRole(new DeleteRoleRequest
            {
                RoleName = roleName
            });

            client.DeleteInstanceProfile(new DeleteInstanceProfileRequest
            {
                InstanceProfileName = roleName
            });
        }

        static string EncodeToBase64(string str)
        {
            byte[] toEncodeAsBytes = System.Text.Encoding.UTF8.GetBytes(str);
            string returnValue = System.Convert.ToBase64String(toEncodeAsBytes);
            return returnValue;
        }
    }
}

