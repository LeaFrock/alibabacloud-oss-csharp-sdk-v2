﻿
using System;

namespace AlibabaCloud.OSS.V2.Credentials
{
    /// <summary>
    /// CredentialsProvideFunc provides a helper wrapping a function value
    /// to satisfy the ICredentialsProvider interface.
    /// </summary>
    [Obsolete("Please use CredentialsProviderFunc instead")]
    public class CredentialsProvideFunc : ICredentialsProvider
    {
        public delegate Credentials GetCredentialsFunc();

        private readonly GetCredentialsFunc _func;
        /// <summary>
        /// Creates an instance of <see cref="CredentialsProvideFunc"/>
        /// </summary>
        /// <param name="func">a function that returns Credentials<see cref="Credentials"/></param>
        public CredentialsProvideFunc(GetCredentialsFunc func) => _func = func;

        /// <inheritdoc/>
        public Credentials GetCredentials()
        {
            return _func();
        }
    }
}
