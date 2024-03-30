using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace proyecto_final_webconfig.Models.Entities
{
    [Table("devices_blacklist")]
    public class DeviceBlacklist
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Column("mac_source")]
        public string MacSource { get; set; }

        [Column("description")]
        public string? Description { get; set; }

        [Column("events_detected")]
        public int EventsDetected { get; set; }

        [Column("timestamp_of_ban")]
        public DateTime TimestampOfBan { get; set; }
    }

}

