﻿
namespace AlibabaCloud.OSS.V2.Credentials
{
    /// <summary>
    /// CredentialsProviderFunc provides a helper wrapping a function value
    /// to satisfy the ICredentialsProvider interface.
    /// </summary>
    public class CredentialsProviderFunc : ICredentialsProvider
    {
        public delegate Credentials GetCredentialsFunc();

        private readonly GetCredentialsFunc _func;
        /// <summary>
        /// Creates an instance of <see cref="CredentialsProviderFunc"/>
        /// </summary>
        /// <param name="func">a function that returns Credentials<see cref="Credentials"/></param>
        public CredentialsProviderFunc(GetCredentialsFunc func) => _func = func;

        /// <inheritdoc/>
        public Credentials GetCredentials()
        {
            return _func();
        }
    }
}
