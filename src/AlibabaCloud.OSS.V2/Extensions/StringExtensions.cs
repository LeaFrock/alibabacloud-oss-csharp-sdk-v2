using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace AlibabaCloud.OSS.V2.Extensions
{
    internal static class StringExtensions
    {

        public static string UrlDecode(this string input)
        {
            // return Uri.UnescapeDataString(input);
            return WebUtility.UrlDecode(input);
        }

        public static string UrlEncode(this string input)
        {
            // https://github.com/dotnet/runtime/issues/111114#issuecomment-2572542965
            // https://github.com/dotnet/runtime/issues/45328#issuecomment-735654691
            // return Uri.EscapeDataString(input);
            var encoded = WebUtility.UrlEncode(input);
            return encoded!.Replace("+", "%20");
        }

        private static bool IsUrlSafeChar(char ch)
        {
            if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))
            {
                return true;
            }

            return ch switch
            {
                '-' or '_' or '.' or '~' or '/' => true,
                _ => false
            };
        }

        public static string UrlEncodePath(this string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;
            var encoded = new StringBuilder(input.Length * 2);
            foreach (var @byte in Encoding.UTF8.GetBytes(input))
            {
                var symbol = (char)@byte;
                if (IsUrlSafeChar(symbol))
                    encoded.Append(symbol);
                else
                    encoded.Append('%').Append($"{(int)symbol:X2}");
            }
            return encoded.ToString();
        }

        public static bool IsEmpty([NotNullWhen(false)] this string? value) => string.IsNullOrWhiteSpace(value);

        public static bool IsNotEmpty([NotNullWhen(true)] this string? value) => !string.IsNullOrWhiteSpace(value);

        public static string JoinToString(this IEnumerable<string> strings, char separator)
#if NETCOREAPP2_0_OR_GREATER
            => string.Join(separator, strings);
#else
            => string.Join(separator.ToString(), strings);
#endif

        // public static string JoinToString(this IEnumerable<string> strings, string separator) => string.Join(separator, strings);

        public static string SafeString(this string? value) => value ?? string.Empty;

        public static string AddScheme(this string input, bool disableSsl)
        {
            if (input != "" && !Regex.IsMatch(input, @"^([^:]+)://"))
            {
                var scheme = Defaults.HttpScheme;
                if (disableSsl)
                {
                    scheme = "http";
                }
                return scheme + "://" + input;
            }
            return input;
        }

        public static bool IsValidRegion(this string input)
        {
            return input != "" && Regex.IsMatch(input, @"^[a-z0-9-]+$");
        }

        public static string ToEndpoint(this string input, bool disableSsl, string type)
        {
            var scheme = disableSsl ? "http" : "https";
            var endpoint = type switch
            {
                "internal" => $"oss-{input}-internal.aliyuncs.com",
                "dual-stack" => $"{input}.oss.aliyuncs.com",
                "accelerate" => "oss-accelerate.aliyuncs.com",
                "overseas" => "oss-accelerate-overseas.aliyuncs.com",
                _ => $"oss-{input}.aliyuncs.com",
            };
            return $"{scheme}://{endpoint}";
        }

        public static Uri? ToUri(this string input)
        {
            try
            {
                return input == "" ? null : new Uri(input);
            }
            catch (Exception)
            {
                // ignored
            }

            return null;
        }

        private static Regex _bucketNameRegex = new(@"^[a-z0-9-]+$");
        public static bool IsValidBucketName(this string value)
        {
            if (value.Length < 3 || value.Length > 64) return false;

#if NETCOREAPP
            if (value.StartsWith('-')) return false;

            if (value.EndsWith('-')) return false;
#else
            if (value.StartsWith("-", StringComparison.Ordinal)) return false;

            if (value.EndsWith("-", StringComparison.Ordinal)) return false;
#endif

            return _bucketNameRegex.IsMatch(value);
        }

        public static bool IsValidObjectName(this string value)
        {
            return value.Length is >= 1 and <= 1024;
        }
    }
}
