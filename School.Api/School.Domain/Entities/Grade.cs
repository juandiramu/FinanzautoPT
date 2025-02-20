namespace School.Domain.Entities
{
	public class Grade : Entity
	{
		//relation with enrrollments
		public Guid EnrollmentId { get; set; }
		public Enrollment? Enrollment { get; set; }

		public decimal Score { get; set; } 
		public DateTime DateRecorded { get; set; }
		public string? Comments { get; set; }
	}
}
