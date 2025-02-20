using System.Diagnostics;

namespace School.Domain.Entities
{
	public class Enrollment : Entity
	{
		//relation with student
		public Guid StudentId { get; set; }
		public Student? Student { get; set; }
		//relation with corse
		public Guid CourseId { get; set; }
		public Course? Course { get; set; }
		// relation with Grades
		public ICollection<Grade> Grades { get; set; } = [];
	}
}
