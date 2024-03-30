using Microsoft.AspNetCore.Mvc;
using proyecto_final_webconfig.Data;
using proyecto_final_webconfig.Models;
using proyecto_final_webconfig.Repository;
using proyecto_final_webconfig.Services;
using System.Diagnostics;

namespace proyecto_final_webconfig.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IStatsRepository statsRepository;

        public HomeController(ILogger<HomeController> logger, IStatsRepository statsRepository)
        {
            _logger = logger;
            this.statsRepository = statsRepository;
        }

        public IActionResult Index()
        {
            //load all the stats from the database
            var stats = statsRepository.GetStatistics();

            return View(stats);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}