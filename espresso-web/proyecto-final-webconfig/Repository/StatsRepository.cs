using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using proyecto_final_webconfig.Data;
using proyecto_final_webconfig.Models.Entities;
using System;
using static Microsoft.AspNetCore.Razor.Language.TagHelperMetadata;

namespace proyecto_final_webconfig.Repository
{
    public class StatsRepository : IStatsRepository
    {
        private readonly EspressoContext espressoContext;

        public StatsRepository(EspressoContext espressoContext)
        {
            this.espressoContext = espressoContext;
        }

        public Stats GetStatistics()
        {
            var data = new Stats();

            data.UsersConnected = espressoContext.Devices.Count(d => d.LastUpDetected >= DateTime.Now.AddMinutes(-1));
            data.RecentIncidents = espressoContext.Events.Count(e => e.Timestamp >= DateTime.Now.AddMinutes(-10));
            data.BanDevices = espressoContext.Devices.Count(e => e.IsBanned);

            data.CantLowSeverity = espressoContext.Events.Include(e => e.TypeDetection).Count(e => e.TypeDetection.Severity == 0);
            data.CantMediumSeverity = espressoContext.Events.Include(e => e.TypeDetection).Count(e => e.TypeDetection.Severity == 1);
            data.CantHighSeverity = espressoContext.Events.Include(e => e.TypeDetection).Count(e => e.TypeDetection.Severity >= 2);

            var uptime = TimeSpan.FromSeconds(Environment.TickCount / 1000);

            int dias = uptime.Days;
            int horas = uptime.Hours;
            int minutos = uptime.Minutes;

            data.Uptime = $"{dias}d - {horas}h : {minutos}m";



            data.CantSmallIncidents = espressoContext.Events.Count(e => e.CantPacketsDetect <= 50);
            data.CantMediumIncidents = espressoContext.Events.Count(e => e.CantPacketsDetect > 50 && e.CantPacketsDetect <= 300);
            data.CantBigIncidents = espressoContext.Events.Count(e => e.CantPacketsDetect > 300);

            return data;
        }


    }
}
