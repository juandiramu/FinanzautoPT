using Microsoft.EntityFrameworkCore;
using School.Domain.Entities;
using School.Domain.Enums;

namespace School.Infrastructure.DataAcces;

public class SchoolDbContext : DbContext
{
	public SchoolDbContext(DbContextOptions<SchoolDbContext> options) : base(options)
	{
	}
	public DbSet<Teacher>? Teachers { get; set; }
	public DbSet<Student>? Students { get; set; }
	public DbSet<Course>? Courses { get; set; }
	public DbSet<Enrollment>? Enrollments { get; set; }
	public DbSet<Grade>? Grades { get; set; }
	protected override void OnModelCreating(ModelBuilder modelBuilder)
	{
		base.OnModelCreating(modelBuilder);

		modelBuilder.Entity<Grade>()
			.Property(g => g.Score)
			.HasPrecision(5, 2);

	
		modelBuilder.Entity<Student>().HasData(
			new Student {Id = Guid.Parse("703d5c54-af34-4e85-8f6f-41c876beed01"), DNI = "100000001", Name = "Juan", LastName = "Pérez", Email = "juan.perez1@school.com", Phone = "3000000001", Semester = 1, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 20) },
			 new Student {Id = Guid.Parse("38f93952-6546-4de5-997f-274591d4e5e5"), DNI = "100000002", Name = "Ana", LastName = "Gómez", Email = "ana.gomez2@school.com", Phone = "3000000002", Semester = 1, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 20) },
	new Student { Id = Guid.Parse("8143a3cb-6e43-4bd3-89ad-9f2f9a54cd53"), DNI = "100000003", Name = "Carlos", LastName = "Rodríguez", Email = "carlos.rodriguez3@school.com", Phone = "3000000003", Semester = 2, State = StudentState.Inactive, CreatedDate = new DateTime(2024, 2, 21) },
	new Student { Id = Guid.Parse("7aa89fb6-a269-42ad-a2af-b25c72707ce5"), DNI = "100000004", Name = "Laura", LastName = "Fernández", Email = "laura.fernandez4@school.com", Phone = "3000000004", Semester = 2, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 21) },
	new Student { Id = Guid.Parse("b51e4cf9-1a32-445b-9e0e-656296435254"), DNI = "100000005", Name = "Pedro", LastName = "Martínez", Email = "pedro.martinez5@school.com", Phone = "3000000005", Semester = 3, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 22) },
	new Student {Id = Guid.Parse("916c3142-29bd-4615-9288-1d45e6203e3c"), DNI = "100000006", Name = "Lucía", LastName = "Sánchez", Email = "lucia.sanchez6@school.com", Phone = "3000000006", Semester = 3, State = StudentState.Inactive, CreatedDate = new DateTime(2024, 2, 22) },
	new Student {Id = Guid.Parse("8d4cf676-8883-4ce0-9f04-1497665f5e00"), DNI = "100000007", Name = "Miguel", LastName = "López", Email = "miguel.lopez7@school.com", Phone = "3000000007", Semester = 4, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 23) },
	new Student { Id = Guid.Parse("536e91e8-5f04-4e23-9000-1b2c6b13be2d"), DNI = "100000008", Name = "Sofía", LastName = "Díaz", Email = "sofia.diaz8@school.com", Phone = "3000000008", Semester = 4, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 23) },
	new Student {Id = Guid.Parse("2d78bee5-5211-4d72-975c-c3264dc7814a"), DNI = "100000009", Name = "Andrés", LastName = "Torres", Email = "andres.torres9@school.com", Phone = "3000000009", Semester = 5, State = StudentState.Inactive, CreatedDate = new DateTime(2024, 2, 24) },
	new Student {Id = Guid.Parse("f69ffc22-e69f-4be9-9869-b659a1156717"), DNI = "100000010", Name = "María", LastName = "Ruiz", Email = "maria.ruiz10@school.com", Phone = "3000000010", Semester = 5, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 24) },

	new Student { Id = Guid.Parse("751f3bce-afa1-4c79-835a-23ed30d83c27"), DNI = "100000011", Name = "Javier", LastName = "Mendoza", Email = "javier.mendoza11@school.com", Phone = "3000000011", Semester = 6, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 25) },
	new Student {Id = Guid.Parse("41c209a0-5a7c-4599-b04d-1b2ef628b814"), DNI = "100000012", Name = "Elena", LastName = "Ortiz", Email = "elena.ortiz12@school.com", Phone = "3000000012", Semester = 6, State = StudentState.Inactive, CreatedDate = new DateTime(2024, 2, 25) },
	new Student {Id = Guid.Parse("d407e17e-148f-4d31-948d-e93b0addc9e1"), DNI = "100000013", Name = "Diego", LastName = "Morales", Email = "diego.morales13@school.com", Phone = "3000000013", Semester = 7, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 26) },
	new Student { Id = Guid.Parse("1d771062-8510-43ed-a960-223ff32e7563"), DNI = "100000014", Name = "Valeria", LastName = "Gutiérrez", Email = "valeria.gutierrez14@school.com", Phone = "3000000014", Semester = 7, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 26) },
	new Student {Id = Guid.Parse("4922b36e-911e-4982-9aa4-68233c7ec037"), DNI = "100000015", Name = "José", LastName = "Ríos", Email = "jose.rios15@school.com", Phone = "3000000015", Semester = 8, State = StudentState.Inactive, CreatedDate = new DateTime(2024, 2, 27) },

	new Student { Id = Guid.Parse("86a00a92-4657-4ce5-a56b-b698c102c2c6"), DNI = "100000016", Name = "Natalia", LastName = "Silva", Email = "natalia.silva16@school.com", Phone = "3000000016", Semester = 8, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 27) },
	new Student { Id = Guid.Parse("d56d7913-9048-42c6-bf74-9d5baf42c866"), DNI = "100000017", Name = "Fernando", LastName = "Jiménez", Email = "fernando.jimenez17@school.com", Phone = "3000000017", Semester = 9, State = StudentState.Active, CreatedDate = new DateTime(2024, 2, 28) },
	new Student { Id = Guid.Parse("522666ed-549b-4bc8-a42d-d1d9c0757c0b"), DNI = "100000018", Name = "Paula", LastName = "Navarro", Email = "paula.navarro18@school.com", Phone = "3000000018", Semester = 9, State = StudentState.Inactive, CreatedDate = new DateTime(2024, 2, 28) },
	new Student { Id = Guid.Parse("2b087ff7-1c74-41b0-acbf-15c7ff1fd43f"), DNI = "100000019", Name = "Alejandro", LastName = "Cabrera", Email = "alejandro.cabrera19@school.com", Phone = "3000000019", Semester = 10, State = StudentState.Active, CreatedDate = new DateTime(2024, 3, 1) },
	new Student { Id = Guid.Parse("d6cb3bf6-12d3-4180-96d2-d3dafb1566d2"), DNI = "100000020", Name = "Camila", LastName = "Estrada", Email = "camila.estrada20@school.com", Phone = "3000000020", Semester = 10, State = StudentState.Active, CreatedDate = new DateTime(2024, 3, 1) }

		);
	}

}
