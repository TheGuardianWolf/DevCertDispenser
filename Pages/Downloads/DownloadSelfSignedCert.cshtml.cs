using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;
using DevCertDispenser.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace DevCertDispenser.Pages.Downloads
{
    public class DownloadSelfSignedCertModel : PageModel
    {
        private readonly ILogger _logger;
        private readonly ICertificateService _certificateService;

        public DownloadSelfSignedCertModel(ILogger<DownloadSelfSignedCertModel> logger, ICertificateService certificateService)
        {
            _logger = logger;
            _certificateService = certificateService;
        }

        public async Task<IActionResult> OnGet(string[] domain)
        {
            if (domain.Length == 0)
            {
                return BadRequest();
            }

            _logger.LogDebug("Domains submitted for self signed certificate: {domain}", domain);


            var payload = await _certificateService.CreateSelfSignedCertificate(domain);

            var zipEntries = new Dictionary<string, byte[]>
            {
            { "cert.crt", payload.Certificate },
            { "cert.key", payload.Key }
            };

            using var zipMs = new MemoryStream();
            using (var zip = new ZipArchive(zipMs, ZipArchiveMode.Create, true))
            {

                foreach (var entry in zipEntries)
                {
                    var zipEntry = zip.CreateEntry(entry.Key);
                    using var fs = new MemoryStream(entry.Value);
                    using var es = zipEntry.Open();
                    fs.CopyTo(es);
                }
            }

            return File(zipMs.ToArray(), "application/zip", "cert.zip");
            
        }
    }
}
