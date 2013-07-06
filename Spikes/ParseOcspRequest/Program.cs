using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;

namespace ParseOcspRequest
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("ParseOcspRequest request.der");
                return -1;
            }

            var path = args[0];

            var bytes = File.ReadAllBytes(path);
            var ocspReq = new OcspReq(bytes);

            Console.WriteLine("OCSP Request Data:");
            Console.WriteLine("    Version: {0} (0x{0:X})", ocspReq.Version);
            Console.WriteLine("    Requestor List:");

            foreach (var req in ocspReq.GetRequestList())
            {
                var certId = req.GetCertID();

                Console.WriteLine("        Certificate ID:");
                Console.WriteLine("          Hash Algorithm: {0} ({1})",
                                  certId.HashAlgOid,
                                  certId.HashAlgOid == OiwObjectIdentifiers.IdSha1.Id ? "sha1" : "unknown");
                Console.WriteLine("          Issuer Name Hash: {0}", certId.GetIssuerNameHash().ToHexString());
                Console.WriteLine("          Issuer Key Hash: {0}", certId.GetIssuerKeyHash().ToHexString());
                Console.WriteLine("          Serial Number: {0}", certId.SerialNumber.ToHexString());
            }

            return 0;
        }
    }

    internal static class HexStringExtensions
    {
        public static string ToHexString(this BigInteger value)
        {
            return value.ToByteArray().ToHexString();
        }

        public static string ToHexString(this byte[] bytes)
        {
            var result = new StringBuilder();
            foreach (var b in bytes)
            {
                result.AppendFormat("{0:X2}", b);
            }

            return result.ToString();
        }
    }
}
