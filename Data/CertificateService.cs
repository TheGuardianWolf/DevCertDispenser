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
        Task<CertificatePackage> CreateSelfSignedCertificate(string mainDomain, IEnumerable<string> altDomains);
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

        private async Task CommandGuard(Task<CommandResult> resultTask)
        {
            var result = await resultTask;
            if (!result.Success)
            {
                var ex = new CertificateIssueException($"Program exit code was not successful: {result.ExitCode}");
                _logger.LogError(ex, "Exit code not success.\nstderr: {stderr}\nstdout: {stdout}", result.StandardError, result.StandardOutput);
                throw ex;
            }
        }

        private async Task<string> CreateCertificateKey()
        {
            var key = Path.GetTempFileName();
            _logger.LogDebug("Key written to {key}", key);

            var args = new[] { "genrsa", "-out", key, "2048" };
            var command = Command.Run("openssl", args, DefaultCommandOptions);
            await CommandGuard(command.Task);

            return key;
        }

        private async Task<CSRPackage> CreateCSR(string certKey, string mainDomain, IEnumerable<string> altDomains)
        {
            var hasAltDomains = (altDomains?.Count() ?? 0) > 0;

            var conf = _conf;

            if (hasAltDomains)
            {
                conf += $@"[ SAN ]
subjectAltName = {string.Join(",", altDomains.Select(d => $"DNS:{d}"))}
";
            }

            var config = Path.GetTempFileName();
            _logger.LogDebug("Config file written to {config}", config);
            await File.WriteAllTextAsync(config, conf);

            var csr = Path.GetTempFileName();
            _logger.LogDebug("CSR written to {csr}", csr);
            var args = new List<string> 
            { 
                "req", "-new", "-sha256", 
                "-key", certKey, 
                "-subj", $"/C=NZ/ST=AKL/O=ACME Inc./CN={mainDomain}", 
                "-out", csr,
                "-config", config
            };

            if (hasAltDomains)
            {
                args.AddRange(new[]
                {
                    "-reqexts", "SAN"
                });
            }

            var command = Command.Run("openssl", args, DefaultCommandOptions);
            try
            {
                await CommandGuard(command.Task);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, string.Join("\n", command.GetOutputAndErrorLines()));
                throw;
            }

            return new CSRPackage
            {
                CSRPath = csr,
                ConfigPath = config,
                UseSAN = hasAltDomains,
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
                "-days", "1825"
            };

            if (csrPackage.UseSAN)
            {
                args.AddRange(new[] 
                {
                    "-extfile", csrPackage.ConfigPath,
                    "-extensions", "SAN" 
                });
            }

            if (File.Exists($"{_caPath}.srl"))
            {
                args.AddRange(new[] { "-CAserial", $"{_caPath}.srl" });
            }
            else
            {
                args.Add("-CAcreateserial");
            }

            var command = Command.Run("openssl", args, DefaultCommandOptions);
            await CommandGuard(command.Task);

            return cert;
        }

        public byte[] GetCACertificate()
        {
            return _caCert;
        }

        public async Task<CertificatePackage> CreateSelfSignedCertificate(string mainDomain, IEnumerable<string> altDomains)
        {
            var keyPath = await CreateCertificateKey();
            var csrPackage = await CreateCSR(keyPath, mainDomain, altDomains);
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
