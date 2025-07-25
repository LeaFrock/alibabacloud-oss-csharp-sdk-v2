﻿
namespace AlibabaCloud.OSS.V2.Credentials
{
    /// <summary>
    /// Explicitly specify the AccessKey pair that you want to use to access OSS.
    /// </summary>
    public class StaticCredentialsProvider : ICredentialsProvider
    {
        private readonly Credentials _credentials;
        /// <summary>
        /// Creates an instance of <see cref="StaticCredentialsProvider"/>
        /// </summary>
        /// <param name="accessKeyId"></param>
        /// <param name="accessKeySecret"></param>
        public StaticCredentialsProvider(string accessKeyId, string accessKeySecret)
        {
            _credentials = new(accessKeyId, accessKeySecret);
        }

        /// <summary>
        /// Creates an instance of <see cref="StaticCredentialsProvider"/>
        /// </summary>
        /// <param name="accessKeyId"></param>
        /// <param name="accessKeySecret"></param>
        /// <param name="securityToken"></param>
        public StaticCredentialsProvider(string accessKeyId, string accessKeySecret, string securityToken)
        {
            _credentials = new(accessKeyId, accessKeySecret, securityToken);
        }

        /// <inheritdoc/>
        public Credentials GetCredentials()
        {
            return _credentials;
        }
    }
}
