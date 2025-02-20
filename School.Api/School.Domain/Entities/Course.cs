namespace School.Domain.Entities
{
	public class Course : Entity
	{
		public string? Name { get; set; }
		public string? Description { get; set; }
		public int Credits { get; set; }

		//relation wuth teacher
		public Guid TeacherId { get; set; }
		public Teacher? Teacher { get; set; }

		//relation with enrrollment
		public ICollection<Enrollment> Enrollments { get; set; } = [];

		

	}
}
