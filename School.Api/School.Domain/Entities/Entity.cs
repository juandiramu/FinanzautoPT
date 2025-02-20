using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace School.Domain.Entities
{
	public class Entity
	{
		public Guid Id { get; set; }
		public DateTime? CreatedDate { get; set; }
		public string? CreatedBy { get; set; }
		public DateTime? LastModifiedDate { get; set; }
		public string? LastModifiedBy { get; set; }
	}
}
