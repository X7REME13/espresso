using Microsoft.AspNetCore.Mvc;
using proyecto_final_webconfig.Data;
using proyecto_final_webconfig.Models;
using proyecto_final_webconfig.Repository;
using proyecto_final_webconfig.Services;
using System.Diagnostics;

namespace proyecto_final_webconfig.Controllers
{
    public class ConfigController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IStatsRepository statsRepository;

        public ConfigController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }
    }
}