using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace School.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddStudents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "Students",
                columns: new[] { "Id", "CreatedBy", "CreatedDate", "DNI", "Email", "LastModifiedBy", "LastModifiedDate", "LastName", "Name", "Phone", "Semester", "State" },
                values: new object[,]
                {
                    { new Guid("1d771062-8510-43ed-a960-223ff32e7563"), null, new DateTime(2024, 2, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000014", "valeria.gutierrez14@school.com", null, null, "Gutiérrez", "Valeria", "3000000014", 7, 0 },
                    { new Guid("2b087ff7-1c74-41b0-acbf-15c7ff1fd43f"), null, new DateTime(2024, 3, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000019", "alejandro.cabrera19@school.com", null, null, "Cabrera", "Alejandro", "3000000019", 10, 0 },
                    { new Guid("2d78bee5-5211-4d72-975c-c3264dc7814a"), null, new DateTime(2024, 2, 24, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000009", "andres.torres9@school.com", null, null, "Torres", "Andrés", "3000000009", 5, 1 },
                    { new Guid("38f93952-6546-4de5-997f-274591d4e5e5"), null, new DateTime(2024, 2, 20, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000002", "ana.gomez2@school.com", null, null, "Gómez", "Ana", "3000000002", 1, 0 },
                    { new Guid("41c209a0-5a7c-4599-b04d-1b2ef628b814"), null, new DateTime(2024, 2, 25, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000012", "elena.ortiz12@school.com", null, null, "Ortiz", "Elena", "3000000012", 6, 1 },
                    { new Guid("4922b36e-911e-4982-9aa4-68233c7ec037"), null, new DateTime(2024, 2, 27, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000015", "jose.rios15@school.com", null, null, "Ríos", "José", "3000000015", 8, 1 },
                    { new Guid("522666ed-549b-4bc8-a42d-d1d9c0757c0b"), null, new DateTime(2024, 2, 28, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000018", "paula.navarro18@school.com", null, null, "Navarro", "Paula", "3000000018", 9, 1 },
                    { new Guid("536e91e8-5f04-4e23-9000-1b2c6b13be2d"), null, new DateTime(2024, 2, 23, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000008", "sofia.diaz8@school.com", null, null, "Díaz", "Sofía", "3000000008", 4, 0 },
                    { new Guid("751f3bce-afa1-4c79-835a-23ed30d83c27"), null, new DateTime(2024, 2, 25, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000011", "javier.mendoza11@school.com", null, null, "Mendoza", "Javier", "3000000011", 6, 0 },
                    { new Guid("7aa89fb6-a269-42ad-a2af-b25c72707ce5"), null, new DateTime(2024, 2, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000004", "laura.fernandez4@school.com", null, null, "Fernández", "Laura", "3000000004", 2, 0 },
                    { new Guid("8143a3cb-6e43-4bd3-89ad-9f2f9a54cd53"), null, new DateTime(2024, 2, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000003", "carlos.rodriguez3@school.com", null, null, "Rodríguez", "Carlos", "3000000003", 2, 1 },
                    { new Guid("86a00a92-4657-4ce5-a56b-b698c102c2c6"), null, new DateTime(2024, 2, 27, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000016", "natalia.silva16@school.com", null, null, "Silva", "Natalia", "3000000016", 8, 0 },
                    { new Guid("8d4cf676-8883-4ce0-9f04-1497665f5e00"), null, new DateTime(2024, 2, 23, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000007", "miguel.lopez7@school.com", null, null, "López", "Miguel", "3000000007", 4, 0 },
                    { new Guid("916c3142-29bd-4615-9288-1d45e6203e3c"), null, new DateTime(2024, 2, 22, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000006", "lucia.sanchez6@school.com", null, null, "Sánchez", "Lucía", "3000000006", 3, 1 },
                    { new Guid("b51e4cf9-1a32-445b-9e0e-656296435254"), null, new DateTime(2024, 2, 22, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000005", "pedro.martinez5@school.com", null, null, "Martínez", "Pedro", "3000000005", 3, 0 },
                    { new Guid("d407e17e-148f-4d31-948d-e93b0addc9e1"), null, new DateTime(2024, 2, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000013", "diego.morales13@school.com", null, null, "Morales", "Diego", "3000000013", 7, 0 },
                    { new Guid("d56d7913-9048-42c6-bf74-9d5baf42c866"), null, new DateTime(2024, 2, 28, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000017", "fernando.jimenez17@school.com", null, null, "Jiménez", "Fernando", "3000000017", 9, 0 },
                    { new Guid("d6cb3bf6-12d3-4180-96d2-d3dafb1566d2"), null, new DateTime(2024, 3, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000020", "camila.estrada20@school.com", null, null, "Estrada", "Camila", "3000000020", 10, 0 },
                    { new Guid("f69ffc22-e69f-4be9-9869-b659a1156717"), null, new DateTime(2024, 2, 24, 0, 0, 0, 0, DateTimeKind.Unspecified), "100000010", "maria.ruiz10@school.com", null, null, "Ruiz", "María", "3000000010", 5, 0 }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("1d771062-8510-43ed-a960-223ff32e7563"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("2b087ff7-1c74-41b0-acbf-15c7ff1fd43f"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("2d78bee5-5211-4d72-975c-c3264dc7814a"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("38f93952-6546-4de5-997f-274591d4e5e5"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("41c209a0-5a7c-4599-b04d-1b2ef628b814"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("4922b36e-911e-4982-9aa4-68233c7ec037"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("522666ed-549b-4bc8-a42d-d1d9c0757c0b"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("536e91e8-5f04-4e23-9000-1b2c6b13be2d"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("751f3bce-afa1-4c79-835a-23ed30d83c27"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("7aa89fb6-a269-42ad-a2af-b25c72707ce5"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("8143a3cb-6e43-4bd3-89ad-9f2f9a54cd53"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("86a00a92-4657-4ce5-a56b-b698c102c2c6"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("8d4cf676-8883-4ce0-9f04-1497665f5e00"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("916c3142-29bd-4615-9288-1d45e6203e3c"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("b51e4cf9-1a32-445b-9e0e-656296435254"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("d407e17e-148f-4d31-948d-e93b0addc9e1"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("d56d7913-9048-42c6-bf74-9d5baf42c866"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("d6cb3bf6-12d3-4180-96d2-d3dafb1566d2"));

            migrationBuilder.DeleteData(
                table: "Students",
                keyColumn: "Id",
                keyValue: new Guid("f69ffc22-e69f-4be9-9869-b659a1156717"));
        }
    }
}
