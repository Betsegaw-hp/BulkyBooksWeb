using BulkyBooksWeb.Data;
using BulkyBooksWeb.Policies;
using BulkyBooksWeb.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using ChapaNET;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddScoped<CategoryService>();
builder.Services.AddScoped<BookService>();
builder.Services.AddScoped<OrderService>();
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<IUserContext, UserContext>();
builder.Services.AddHttpContextAccessor(); // Required for IHttpContextAccessor

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Add Chapa configuration
var chapaSecretKey = builder.Configuration["Chapa:SecretKey"];
if (string.IsNullOrEmpty(chapaSecretKey))
{
    throw new ArgumentNullException(nameof(chapaSecretKey), "Chapa secret key is not configured.");
}
builder.Services.AddSingleton(new Chapa(chapaSecretKey));


builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Auth/Login";
        options.AccessDeniedPath = "/Auth/AccessDenied";
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin"));
    options.AddPolicy("AuthorOnly", policy => policy.RequireRole("author"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("user"));
    options.AddPolicy("BookOwnerOrAdmin", policy =>
        policy.Requirements.Add(new BookOwnerOrAdminRequirement()));
    options.AddPolicy("OrderOwnerOrAdmin", policy =>
        policy.Requirements.Add(new OrderOwnerOrAdminRequirement()));
});

builder.Services.AddSingleton<IAuthorizationHandler, BookOwnerOrAdminHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, OrderOwnerOrAdminHandler>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
