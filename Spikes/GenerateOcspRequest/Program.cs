using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace GenerateOcspRequest
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("OcspSpike thumbprint outputfile.der");
                return -1;
            }

            var subjectThumbprint = args[0];    // e.g. "E14D7CE65418771EF189E6F107FEFBEB13874CA5"
            var destinationPath = args[1];

            var subjectCertificate = GetCertificate(StoreName.My, StoreLocation.CurrentUser,
                                                    X509FindType.FindByThumbprint, subjectThumbprint);
            var issuerCertificate = GetIssuerCertificate(subjectCertificate);

            // Convert from .NET certificates to Bouncy Castle certificates.
            var subjectCert = DotNetUtilities.FromX509Certificate(subjectCertificate);
            var issuerCert = DotNetUtilities.FromX509Certificate(issuerCertificate);

            byte[] encodedRequest = GenerateOcspRequest(subjectCert.SerialNumber, issuerCert);
            File.WriteAllBytes(destinationPath, encodedRequest);
            return 0;
        }

        private static byte[] GenerateOcspRequest(BigInteger subjectSerialNumber, X509Certificate issuerCert)
        {
            // We need a request generator.
            var generator = new OcspReqGenerator();

            // Then we add the certificate we're asking about to it.
            generator.AddRequest(new CertificateID(CertificateID.HashSha1, issuerCert, subjectSerialNumber));

            // Then we generate the DER-encoded request.
            var req = generator.Generate();
            return req.GetEncoded();
        }

        private static X509Certificate2 GetIssuerCertificate(X509Certificate2 subjectCertificate)
        {
            // Don't check online for revocation; that's what this spike is attempting to do, so there's no point in letting .NET do it.
            var policy = new X509ChainPolicy {RevocationMode = X509RevocationMode.NoCheck};
            var chain = new X509Chain {ChainPolicy = policy};

            // We need the certificate chain, in order to get the certificate and its issuer.
            chain.Build(subjectCertificate);
            if (chain.ChainElements.Count == 1) // Self-signed.
                return chain.ChainElements[0].Certificate;

            if (chain.ChainElements.Count >= 2)
                return chain.ChainElements[1].Certificate;

            throw new InvalidOperationException("Could not discover issuer certificate by building certificate chain.");
        }

        private static X509Certificate2 GetCertificate(StoreName storeName,
                                                       StoreLocation storeLocation,
                                                       X509FindType findByThumbprint,
                                                       object findValue)
        {
            var store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                return
                    store.Certificates
                         .Find(findByThumbprint, findValue, validOnly: false)
                         .Cast<X509Certificate2>()
                         .FirstOrDefault();
            }
            finally
            {
                store.Close();
            }
        }
    }
}
