using Medallion.Shell;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace DevCertDispenser.Data
{
    public class CertificateIssueException : Exception
    {
        public CertificateIssueException() : base() { }
        public CertificateIssueException(string message) : base(message) { }
    }

    public interface ICertificateService
    {
        Task<CertificatePackage> CreateSelfSignedCertificate(IEnumerable<string> domains);
        byte[] GetCACertificate();
    }

    public class CertificateService : ICertificateService
    {
        private readonly string _caPath;
        private readonly byte[] _caCert;
        private readonly string _conf;
        private readonly ILogger _logger;

        public CertificateService(ILogger<CertificateService> logger, IConfiguration configuration)
        {
            _logger = logger;
            _caPath = configuration.GetValue<string>("Certificate:CAPath");
            
            var _confPath = configuration.GetValue<string>("Certificate:ConfPath");

            _caCert = File.ReadAllBytes($"{_caPath}.crt");
            _conf = File.ReadAllText(_confPath);
        }
        private void DefaultCommandOptions(Shell.Options options)
        {
            options.Timeout(new TimeSpan(0, 0, 5));
        }

        private async Task<CommandResult> RunCommand(string executable, IEnumerable<object> args)
        {
            var command = Command.Run(executable, args, DefaultCommandOptions);

            try
            {
                var result = await command.Task;
                if (!result.Success)
                {
                    throw new CertificateIssueException($"Program exit code was not successful: {result.ExitCode}");
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Command error.\nstderr: {stderr}\nstdout: {stdout}", command.StandardError, command.StandardOutput);
                throw;
            }
        }

        private async Task<string> CreateCertificateKey()
        {
            var key = Path.GetTempFileName();
            _logger.LogDebug("Key written to {key}", key);

            var args = new[] { "genrsa", "-out", key, "2048" };
            await RunCommand("openssl", args);

            return key;
        }

        private async Task<CSRPackage> CreateCSR(string certKey, IEnumerable<string> domains)
        {
            var conf = _conf + $@"authorityKeyIdentifier = keyid,issuer
basicConstraints = critical, CA:FALSE
extendedKeyUsage = serverAuth, clientAuth
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
[ SAN ]
subjectAltName = {string.Join(",", domains.Select(d => $"DNS:{d}"))}
";

            var config = Path.GetTempFileName();
            _logger.LogDebug("Config file written to {config}", config);
            await File.WriteAllTextAsync(config, conf);

            var csr = Path.GetTempFileName();
            _logger.LogDebug("CSR written to {csr}", csr);
            var args = new List<string> 
            { 
                "req", "-new", "-sha256", 
                "-key", certKey, 
                "-subj", $"/C=NZ/ST=AKL/O=ACME Inc./CN={domains.First()}", 
                "-out", csr,
                "-config", config,
                "-reqexts", "SAN"
            };

            await RunCommand("openssl", args);

            return new CSRPackage
            {
                CSRPath = csr,
                ConfigPath = config
            };
        }

        private async Task<string> CreateCertificate(CSRPackage csrPackage)
        {
            var cert = Path.GetTempFileName();
            _logger.LogDebug("Certificate written to {cert}", cert);
            var args = new List<string> 
            { 
                "x509", "-req", "-sha256",
                "-in", csrPackage.CSRPath, 
                "-CA", $"{_caPath}.crt", 
                "-CAkey", $"{_caPath}.key", 
                "-out", cert, 
                "-days", "1825",
                "-extfile", csrPackage.ConfigPath,
                "-extensions", "SAN"
            };

            if (File.Exists($"{_caPath}.srl"))
            {
                args.AddRange(new[] { "-CAserial", $"{_caPath}.srl" });
            }
            else
            {
                args.Add("-CAcreateserial");
            }

            await RunCommand("openssl", args);

            return cert;
        }

        public byte[] GetCACertificate()
        {
            return _caCert;
        }

        public async Task<CertificatePackage> CreateSelfSignedCertificate(IEnumerable<string> domains)
        {
            var keyPath = await CreateCertificateKey();
            var csrPackage = await CreateCSR(keyPath, domains);
            var certPath = await CreateCertificate(csrPackage);

            var files = await Task.WhenAll(File.ReadAllBytesAsync(certPath), File.ReadAllBytesAsync(keyPath));

            var payload = new CertificatePackage
            {
                Certificate = files[0],
                Key = files[1]
            };

            return payload;
        }
    }
}
