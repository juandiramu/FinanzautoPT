using School.Domain.Enums;

namespace School.Application.Dtos
{
	public class EditStudentDto
	{
		public Guid Id { get; set; }
		public string? DNI { get; set; }
		public string? Name { get; set; }
		public string? LastName { get; set; }
		public string? Email { get; set; }
		public string? Phone { get; set; }
		public int Semester { get; set; }
		public StudentState State { get; set; }
	}
}
