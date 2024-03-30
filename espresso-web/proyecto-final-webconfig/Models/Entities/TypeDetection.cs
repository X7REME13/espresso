using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace proyecto_final_webconfig.Models.Entities
{
    [Table("types_detection")]
    public class TypeDetection
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [Column("id")]
        public int Id { get; set; }

        [Column("description_short")]
        public string DescriptionShort { get; set; }

        [Column("description_long")]
        public string DescriptionLong { get; set; }

        [Column("severity")]
        public int Severity { get; set; }

        [Column("file_name")]
        public string FileName { get; set; }
    }

}

