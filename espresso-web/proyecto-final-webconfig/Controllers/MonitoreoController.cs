using Microsoft.AspNetCore.Mvc;
using proyecto_final_webconfig.Data;
using proyecto_final_webconfig.Models;
using proyecto_final_webconfig.Services;
using System.Diagnostics;

namespace proyecto_final_webconfig.Controllers
{
    public class MonitoreoController : Controller
    {
        private readonly ILogger<MonitoreoController> _logger;
        private readonly IEventsService eventsService;

        public MonitoreoController(ILogger<MonitoreoController> logger, IEventsService eventsService)
        {
            _logger = logger;
            this.eventsService = eventsService;
        }

        public async Task<IActionResult> List()
        {
            var events = await eventsService.GetAllRecentsEvents();

            return View(events);
        }

        public async Task<IActionResult> ListByDevice(string mac)
        {
            //TODO: get device for MAC and send ID to view
            ViewBag.IdDevice = 0;

            var events = await eventsService.GetAllRecentsEventsByDevice(mac);

            return View("ListDevice", events);
        }
        public async Task<IActionResult> Details(int id)
        {
            //get all entities from the database events
            var singleEvent = await eventsService.GetEventByID(id);

            return View(singleEvent);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}