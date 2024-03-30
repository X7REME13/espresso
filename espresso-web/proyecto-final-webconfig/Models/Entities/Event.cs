using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace proyecto_final_webconfig.Models.Entities
{


    [Table("events")]
    public class Event
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Column("ip_source")]
        public string? IpSource { get; set; }

        [Column("mac_source")]
        public string MacSource { get; set; }

        [Column("oui_source")]
        public string? OuiSource { get; set; }

        //[Column("ip_destination")]
        //public string IpDestination { get; set; }

        //[Column("mac_destination")]
        //public string MacDestination { get; set; }

        //[Column("oui_destination")]
        //public string? OuiDestination { get; set; }

        [Column("cant_packets_detect")]
        public int CantPacketsDetect { get; set; }

        [Column("timestamp")]
        public DateTime Timestamp { get; set; }

        [Column("id_type_detection")]
        public int IdTypeDetection { get; set; }

        [ForeignKey("IdTypeDetection")]
        public TypeDetection TypeDetection { get; set; }
    }

}

