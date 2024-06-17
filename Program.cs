using Azure.Identity;
using KeyVaultYouTubeDemo;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var keyVaultUri = new Uri($"https://{builder.Configuration["KeyVaultName"]}.vault.azure.net/");

builder.Configuration.AddAzureKeyVault(
    keyVaultUri,
    new DefaultAzureCredential(),
    new CustomSecretManager("KeyVaultDemo")
);

// Add KeyVault Configuration
builder.AddKeyVaultConfiguration();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<TodoDbContext>(options =>
{
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        sqlOptions => sqlOptions.EnableRetryOnFailure()
    );
});

var app = builder.Build();

using var scope = app.Services.CreateScope();
var db = scope.ServiceProvider.GetService<TodoDbContext>();
db?.Database.EnsureCreatedAsync();

app.UseSwagger();
app.UseSwaggerUI();
app.UseDeveloperExceptionPage();

app.UseHttpsRedirection();

app.MapGet("/todo", async (TodoDbContext context) =>
       await context.Todos.ToListAsync())
   .WithName("Get All Todos")
   .WithOpenApi();

app.MapGet("/todo/{id:int}", async (int id, TodoDbContext context) =>
    await context.Todos.FindAsync(id)
        is { } todo
        ? Results.Ok(todo)
        : Results.NotFound())
   .WithName("Get Todo by Id")
   .WithOpenApi();

app.MapPost("/todo", async (Todo todo, TodoDbContext context) =>
    {
        await context.Todos.AddAsync(todo);
        await context.SaveChangesAsync();
        
        return Results.Created($"/todo/{todo.Id}", todo);
    })
   .WithName("Add Todo Item")
   .WithOpenApi();

app.Run();
