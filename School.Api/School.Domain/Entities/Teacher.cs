using School.Domain.Enums;

namespace School.Domain.Entities
{
	public class Teacher: Person
	{
		public string? Especialidad { get; set; }
		public ContractType ContractType { get; set; }

		public Teacher() { }

		public Teacher(string? name, string? lastname, string? email, string? phone, string? especialidad, ContractType type) {
			Name = name;
			LastName = lastname;
			Email = email;
			Phone = phone;
			Especialidad = especialidad;
			ContractType = type;
		}
	}
}
