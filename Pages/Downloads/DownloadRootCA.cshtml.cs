using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DevCertDispenser.Data;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace DevCertDispenser.Pages.Downloads
{
    public class DownloadRootCAModel : PageModel
    {
        private readonly ILogger _logger;
        private readonly ICertificateService _certificateService;

        public DownloadRootCAModel(ILogger<DownloadSelfSignedCertModel> logger, ICertificateService certificateService)
        {
            _logger = logger;
            _certificateService = certificateService;
        }

        public IActionResult OnGet()
        {
            _logger.LogDebug("Downloading root ca");

            var fileBytes = _certificateService.GetCACertificate();

            return File(fileBytes, "application/force-download", "ca.crt");
        }
    }
}
