namespace School.Domain.Entities
{
	public class Person : Entity
	{
		public string? DNI { get; set; }
		public string? Name { get; set; }
		public string? LastName { get; set; }
		public string? Email { get; set; }
		public string? Phone { get; set; }
	}
}
