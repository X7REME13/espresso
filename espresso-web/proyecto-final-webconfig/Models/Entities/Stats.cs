namespace proyecto_final_webconfig.Models.Entities
{
    public class Stats
    {
        public int UsersConnected { get; set; }
        public int RecentIncidents { get; set; }
        public int BanDevices { get; set; }

        public int CantSmallIncidents { get; set; }
        public int CantMediumIncidents { get; set; }
        public int CantBigIncidents { get; set; }

        public string? Uptime { get; set; }

        public int CantLowSeverity { get; set; }
        public int CantMediumSeverity { get; set; }
        public int CantHighSeverity { get; set; }



    }
}
