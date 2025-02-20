using School.Domain.Enums;

namespace School.Domain.Entities
{
	public class Student : Person
	{
		public int Semester {  get; set; }
		public StudentState State { get; set; }
		public Student() { }
		public Student(string? dni, string? name, string? lastname, string? email, string? phone, int semester, StudentState state)
		{
			DNI = dni;
			Name = name;
			LastName = lastname;
			Email = email;
			Phone = phone;
			Semester = semester;
			State = state;
			
		}
		public void EditStudent(string? dni, string? name, string? lastname, string? email, string? phone, int semester, StudentState state)
		{
			DNI = dni;
			Name = name;
			LastName = lastname;
			Email = email;
			Phone = phone;
			Semester = semester;
			State = state;
		}

	}
}
