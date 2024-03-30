using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace proyecto_final_webconfig.Models.Entities
{
    [Table("devices")]
    public class Device
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [Column("mac_source")]
        public string MacSource { get; set; } = "";

        [Column("description")]
        public string? Description { get; set; }

        [Column("events_detected")]
        public int? EventsDetected { get; set; }

        [Column("last_attack_detected")]
        public DateTime? LastAttackDetected { get; set; }

        [Column("last_up_detected")]
        public DateTime LastUpDetected { get; set; }

        [Column("time_of_ban")]
        public DateTime? TimeOfBan { get; set; }

        [Column("is_banned")]
        public bool IsBanned { get; set; }

        [Column("is_suspicious")]
        public bool IsSuspicious { get; set; }

        [Column("is_ignored")]
        public bool IsIgnored { get; set; }
    }
}



