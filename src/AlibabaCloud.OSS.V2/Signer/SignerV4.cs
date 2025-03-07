using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AlibabaCloud.OSS.V2.Extensions;

namespace AlibabaCloud.OSS.V2.Signer
{
    public class SignerV4 : ISigner
    {
        private const string UnsignedPayload = "UNSIGNED-PAYLOAD";
        private const string DateTimeFormat = "yyyyMMdd'T'HHmmss'Z'";
        private const string DateFormat = "yyyyMMdd";
        private const string Rfc822DateFormat = @"ddd, dd MMM yyyy HH:mm:ss \G\M\T";

        public void Sign(SigningContext signingContext)
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(signingContext.Request);
            ArgumentNullException.ThrowIfNull(signingContext.Credentials);
            ArgumentNullException.ThrowIfNull(signingContext.Region);
            ArgumentNullException.ThrowIfNull(signingContext.Product);
#else
            ThrowIfNull(signingContext.Request, nameof(signingContext.Request));
            ThrowIfNull(signingContext.Credentials, nameof(signingContext.Credentials));
            ThrowIfNull(signingContext.Region, nameof(signingContext.Region));
            ThrowIfNull(signingContext.Product, nameof(signingContext.Product));

            static void ThrowIfNull(object? arg, string paramName)
            {
                if (arg is null)
                {
                    throw new ArgumentNullException($"{nameof(signingContext)}.{paramName}");
                }
            }
#endif

            if (signingContext.AuthMethodQuery)
                AuthQuery(signingContext);
            else
                AuthHeader(signingContext);
        }

        private static void AuthQuery(SigningContext signingContext)
        {
            var request = signingContext.Request;
            var credentials = signingContext.Credentials;
            var region = signingContext.Region ?? "";
            var product = signingContext.Product ?? "";

            // Date
            var signTime = signingContext.SignTime ?? DateTime.UtcNow;
            var datetime = FormatDateTime(signTime);
            var date = FormatDate(signTime);

            // Expiration 
            var expiration = signingContext.Expiration ?? DateTime.UtcNow.AddMinutes(15);
            var expires = ((long)expiration.Subtract(signTime).TotalSeconds).ToString(CultureInfo.InvariantCulture);

            // Scope
            var scope = $"{date}/{region}/{product}/aliyun_v4_request";

            // Headers
            var headers = request!.Headers;

            var additionalHeaders = GetAdditionalHeaders(headers, signingContext.AdditionalHeaders);
            additionalHeaders.Sort();

            // Credentials information
            var parameters = new Dictionary<string, string>();
            if (credentials!.SecurityToken.IsNotEmpty()) parameters.Add("x-oss-security-token", credentials.SecurityToken);
            parameters.Add("x-oss-signature-version", "OSS4-HMAC-SHA256");
            parameters.Add("x-oss-date", datetime);
            parameters.Add("x-oss-expires", expires);
            parameters.Add("x-oss-credential", $"{credentials.AccessKeyId}/{scope}");

            if (additionalHeaders.Count > 0)
                parameters.Add("x-oss-additional-headers", additionalHeaders.JoinToString(':'));

            // update query 
            StringBuilder sb = new(64);
            AppendAsQueryUrl(sb, parameters, encoded: false);
            var queryStr = sb.ToString();
            request.RequestUri = request.RequestUri.AppendToQuery(queryStr);

            // CanonicalRequest
            var canonicalRequest = CanonicalizeRequest(
                request,
                ResourcePath(signingContext.Bucket, signingContext.Key),
                headers,
                additionalHeaders
            );

            // StringToSign
            var stringToSign = CalcStringToSign(datetime, scope, canonicalRequest);

            // Signature
            var signature = CalcSignature(credentials.AccessKeySecret, date, region, product, stringToSign);

            // Credential
            request.RequestUri = request.RequestUri.AppendToQuery($"x-oss-signature={signature.UrlEncode()}");

            //Console.WriteLine("canonicalRequest:{0}\n", canonicalRequest);
            //Console.WriteLine("stringToSign:{0}\n", stringToSign);
            //Console.WriteLine("signature:{0}\n", signature);
            //update
            signingContext.Request = request;
            signingContext.Expiration = expiration;
            signingContext.StringToSign = stringToSign;
        }

        private static void AuthHeader(SigningContext signingContext)
        {
            var request = signingContext.Request;
            var credentials = signingContext.Credentials;
            var region = signingContext.Region ?? "";
            var product = signingContext.Product ?? "";

            // Date
            var signTime = signingContext.SignTime ?? DateTime.UtcNow;
            var datetime = FormatDateTime(signTime);
            var date = FormatDate(signTime);
            var datetimeGmt = FormatRfc822Date(signTime);

            // Scope
            var scope = $"{date}/{region}/{product}/aliyun_v4_request";

            // Credentials information
            if (credentials!.SecurityToken.IsNotEmpty())
                request!.Headers["x-oss-security-token"] = credentials.SecurityToken;

            // Other Headers
            request!.Headers["x-oss-content-sha256"] = UnsignedPayload;
            request.Headers["x-oss-date"] = datetime;
            request.Headers["Date"] = datetimeGmt;

            // lower key & Sorted Headers
            // the headers is OrdinalIgnoreCase
            var headers = request.Headers;

            var additionalHeaders = GetAdditionalHeaders(headers, signingContext.AdditionalHeaders);
            additionalHeaders.Sort();

            // CanonicalRequest
            var canonicalRequest = CanonicalizeRequest(
                request,
                ResourcePath(signingContext.Bucket, signingContext.Key),
                headers,
                additionalHeaders
            );

            // StringToSign
            var stringToSign = CalcStringToSign(datetime, scope, canonicalRequest);

            // Signature
            var signature = CalcSignature(credentials.AccessKeySecret, date, region, product, stringToSign);

            // Credential
            var sb = new StringBuilder();
            sb.AppendFormat("OSS4-HMAC-SHA256 Credential={0}/{1}", credentials.AccessKeyId, scope);
            if (additionalHeaders.Count > 0) sb.AppendFormat(",AdditionalHeaders={0}", additionalHeaders.JoinToString(';'));
            sb.AppendFormat(",Signature={0}", signature);

            request.Headers["Authorization"] = sb.ToString();

            //Console.WriteLine("canonicalRequest:{0}\n", canonicalRequest);
            //Console.WriteLine("stringToSign:{0}\n", stringToSign);
            //Console.WriteLine("signature:{0}\n", signature);

            //update
            signingContext.StringToSign = stringToSign;
        }

        private static string FormatDateTime(DateTime time)
        {
            return time.ToUniversalTime().ToString(DateTimeFormat, CultureInfo.InvariantCulture);
        }

        private static string FormatDate(DateTime time)
        {
            return time.ToUniversalTime().ToString(DateFormat, CultureInfo.InvariantCulture);
        }

        public static string FormatRfc822Date(DateTime time)
        {
            return time.ToUniversalTime().ToString(Rfc822DateFormat, CultureInfo.InvariantCulture);
        }

        private static string ResourcePath(string? bucket, string? key)
        {
            var resourcePath = "/" + (bucket ?? string.Empty) + (key != null ? "/" + key : "");
            if (bucket != null && key == null) resourcePath += "/";
            return resourcePath;
        }

        private static string CanonicalizeRequest(
            RequestMessage request,
            string resourcePath,
            IDictionary<string, string> headers,
            List<string> additionalHeaders
        )
        {
            /*
                Canonical Request
                HTTP Verb + "\n" +
                Canonical URI + "\n" +
                Canonical Query String + "\n" +
                Canonical Headers + "\n" +
                Additional Headers + "\n" +
                Hashed PayLoad
            */
            var httpMethod = request.Method.ToUpperInvariant();

            // Canonical Uri
            var canonicalUri = resourcePath.UrlEncodePath();

            // Canonical Query
            var sortedParameters = new SortedDictionary<string, string>(StringComparer.Ordinal);

            if (request.RequestUri.Query.IsNotEmpty())
            {
                var query = request.RequestUri.Query;

#if NET9_0_OR_GREATER
                // Task the case "?a=1&b&c=&d=1=2=3" for reference.
                var querySpan = query.StartsWith('?') ? query.AsSpan(1) : query.AsSpan();
                Span<Range> rangeBuffer = stackalloc Range[3];
                foreach (var range in querySpan.Split('&'))
                {
                    var pairSpan = querySpan[range];
                    if (pairSpan.IsEmpty)
                    {
                        continue;
                    }
                    var partCount = pairSpan.Split(rangeBuffer, '=');
                    switch (partCount)
                    {
                        case 1:
                            sortedParameters.Add(new(pairSpan[rangeBuffer[0]]), string.Empty);
                            break;
                        case 2:
                            sortedParameters.Add(new(pairSpan[rangeBuffer[0]]), new(pairSpan[rangeBuffer[1]]));
                            break;
                        default:
                            // It should be impossible to get here. Shall we throw an exception?
                            // Take `d=1=2=3` for example to explain why the length of rangeBuffer is 3:
                            // the output will be `[d, 1, 2=3]` if the length is 3;
                            // and the output will be `[d, 1=2=3]` if the length is 2.
                            // Currently we just follow the same logic(which picks the former 2 elements) as the logic in other .NET versions.
                            sortedParameters.Add(new(pairSpan[rangeBuffer[0]]), new(pairSpan[rangeBuffer[1]]));
                            break;
                    }
                }
#elif NETCOREAPP2_0_OR_GREATER
                if (query.StartsWith('?')) query = query.Substring(1);

                foreach (var param in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = param.Split('=', 2);
                    sortedParameters.Add(parts[0], parts.Length == 1 ? "" : parts[1]);
                }
#else
                if (query.StartsWith("?", StringComparison.Ordinal)) query = query.Substring(1);

                foreach (var param in query.Split(['&'], StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = param.Split(['='], 2);
                    sortedParameters.Add(parts[0], parts.Length == 1 ? "" : parts[1]);
                }
#endif
            }

            var strBuilder = new StringBuilder();
            AppendAsQueryUrl(strBuilder, sortedParameters, encoded: true);
            var canonicalQueryString = strBuilder.ToString();

            var canonicalHeaderString = CanonicalizeHeaders(headers, additionalHeaders);

            // Additional Headers
            var additionalHeadersString = additionalHeaders.JoinToString(';');

            var hashBody = CanonicalizeBodyHash(headers);

            strBuilder.Clear();
            var canonicalRequest = strBuilder
                .Append(httpMethod).Append('\n') // DO NOT use AppendLine(), because it might add \r\n in some OS environments.
                .Append(canonicalUri).Append('\n')
                .Append(canonicalQueryString).Append('\n')
                .Append(canonicalHeaderString).Append('\n')
                .Append(additionalHeadersString).Append('\n')
                .Append(hashBody);
            return canonicalRequest.ToString();
        }

        private static string CanonicalizeHeaders(IDictionary<string, string> headers, List<string> additionalHeaders)
        {
            if (headers.Count == 0)
                return string.Empty;

            var addHeadersMap = new Dictionary<string, string>();
            foreach (var header in additionalHeaders) addHeadersMap[header.ToLowerInvariant()] = string.Empty;

            var sortedHeaderMap = new SortedDictionary<string, string>(StringComparer.Ordinal);

            foreach (var header in headers)
            {
                if (header.Value == null) continue;
                var lowerKey = header.Key.ToLowerInvariant();

                if (IsDefaultSignedHeader(lowerKey) ||
                    addHeadersMap.ContainsKey(lowerKey))
                    sortedHeaderMap[lowerKey] = header.Value.Trim();
            }

            var sb = new StringBuilder();
            foreach (var header in sortedHeaderMap) sb.AppendFormat("{0}:{1}\n", header.Key, header.Value.Trim());

            return sb.ToString();
        }

        private static string CanonicalizeBodyHash(IDictionary<string, string> headers)
        {
            return headers.TryGetValue("x-oss-content-sha256", out var value) ? value : UnsignedPayload;
        }

        private static bool IsDefaultSignedHeader(string lowerKey)
        {
            return lowerKey == "content-type" ||
                lowerKey == "content-md5" ||
                lowerKey.StartsWith("x-oss-");
        }

        private static List<string> GetAdditionalHeaders(
            IDictionary<string, string> headers,
            List<string>? additionalHeaders
        )
        {
            if (additionalHeaders is not { Count: > 0 } || headers.Count == 0)
            {
                return [];
            }

            var keys = new List<string>();

            foreach (var k in additionalHeaders)
            {
                var lowK = k.ToLowerInvariant();
                if (!IsDefaultSignedHeader(lowK) && headers.ContainsKey(lowK))
                {
                    keys.Add(lowK);
                }
            }

            return keys;
        }

        private static string CalcStringToSign(string datetime, string scope, string canonicalRequest)
        {
            /*
            StringToSign
            "OSS4-HMAC-SHA256" + "\n" +
            TimeStamp + "\n" +
            Scope + "\n" +
            Hex(SHA256Hash(Canonical Request))
            */

#if NET5_0_OR_GREATER
            var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest));
#else
            using var hash = SHA256.Create();
            var hashBytes = hash.ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest));
#endif

            var hexStr = ToHexString(hashBytes, true);
            return $"OSS4-HMAC-SHA256\n" +
                $"{datetime}\n" +
                $"{scope}\n" +
                $"{hexStr}";
        }

        private static string CalcSignature(
            string accessKeySecret,
            string date,
            string region,
            string product,
            string stringToSign
        )
        {
            var ksecret = Encoding.UTF8.GetBytes("aliyun_v4" + accessKeySecret);

#if NET6_0_OR_GREATER

            var hashDate = ComputeHash(ksecret, date);
            var hashRegion = ComputeHash(hashDate, region);
            var hashProduct = ComputeHash(hashRegion, product);
            var signingKey = ComputeHash(hashProduct, "aliyun_v4_request");
            var signature = ComputeHash(signingKey, stringToSign);

            static byte[] ComputeHash(byte[] key, string input)
            {
                var source = Encoding.UTF8.GetBytes(input);
                return HMACSHA256.HashData(key, source);
            }
#else
            using var kha = new HMACSHA256();
            var hashDate = ComputeHash(kha, ksecret, date);
            var hashRegion = ComputeHash(kha, hashDate, region);
            var hashProduct = ComputeHash(kha, hashRegion, product);
            var signingKey = ComputeHash(kha, hashProduct, "aliyun_v4_request");
            var signature = ComputeHash(kha, signingKey, stringToSign);

            static byte[] ComputeHash(HMACSHA256 hash, byte[] key, string input)
            {
                var source = Encoding.UTF8.GetBytes(input);
                hash.Key = key;
                return hash.ComputeHash(source);
            }
#endif
            //Console.WriteLine("ksecret:{0}\n", OssUtils.ToHexString(ksecret, true));
            //Console.WriteLine("hashDate:{0}\n", OssUtils.ToHexString(hashDate, true));
            //Console.WriteLine("hashRegion:{0}\n", OssUtils.ToHexString(hashRegion, true));
            //Console.WriteLine("hashProduct:{0}\n", OssUtils.ToHexString(hashProduct, true));
            //Console.WriteLine("signature:{0}\n", OssUtils.ToHexString(signature, true));

            return ToHexString(signature, true);
        }

        internal static string ToHexString(byte[] data, bool lowercase)
        {
#if NET9_0_OR_GREATER
            return lowercase ? Convert.ToHexStringLower(data) : Convert.ToHexString(data);
#elif NET5_0_OR_GREATER
            var hex = Convert.ToHexString(data);
            return lowercase ? hex.ToLowerInvariant() : hex;
#else
            var sb = new StringBuilder(data.Length * 2);
            var format = lowercase ? "x2" : "X2";
            for (var i = 0; i < data.Length; i++) sb.Append(data[i].ToString(format));
            return sb.ToString();
#endif
        }

        private static void AppendAsQueryUrl(StringBuilder sb, IEnumerable<KeyValuePair<string, string>> pairs, bool encoded)
        {
            if (encoded)
            {
                foreach (var item in pairs)
                {
                    sb.Append(item.Key);
                    if (!item.Value.IsEmpty())
                    {
                        sb.Append('=').Append(item.Value).Append('&');
                    }
                }
            }
            else
            {
                foreach (var item in pairs)
                {
                    sb.Append(item.Key.UrlEncode());
                    if (!item.Value.IsEmpty())
                    {
                        sb.Append('=').Append(item.Value.UrlEncode()).Append('&');
                    }
                }
            }
            if (sb[sb.Length - 1] == '&')
            {
                sb.Length--;
            }
        }
    }
}
