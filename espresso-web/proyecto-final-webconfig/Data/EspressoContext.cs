using Microsoft.EntityFrameworkCore;
using proyecto_final_webconfig.Models.Entities;

namespace proyecto_final_webconfig.Data
{
    public class EspressoContext : DbContext
    {
        public EspressoContext(DbContextOptions<EspressoContext> options) : base(options)
        {
        }

        public DbSet<Event> Events { get; set; }
        public DbSet<Device> Devices { get; set; }
        public DbSet<TypeDetection> TypesDetection { get; set; }
        public DbSet<DeviceBlacklist> DeviceBlacklists { get; set; }


    }
}

