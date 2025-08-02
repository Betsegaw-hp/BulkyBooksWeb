using BulkyBooksWeb.Data;
using BulkyBooksWeb.Policies;
using BulkyBooksWeb.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using ChapaNET;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using BulkyBooksWeb.Models;

var builder = WebApplication.CreateBuilder(args);

// Debugging line
Console.WriteLine($"[DEBUG] Current ASPNETCORE_ENVIRONMENT: {builder.Environment.EnvironmentName}");


// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseLazyLoadingProxies()
            .UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddScoped<CategoryService>();
builder.Services.AddScoped<BookService>();
builder.Services.AddScoped<OrderService>();
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<IUserContext, UserContext>();
builder.Services.AddScoped<UserMigrationService>();
builder.Services.AddScoped<DataSeedService>();
builder.Services.AddHttpContextAccessor(); // Required for IHttpContextAccessor

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Lax; // Allow redirects from external sites
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; //  'Always' for secure cookies in production
});

builder.Services.AddControllersWithViews()
    .AddCookieTempDataProvider();
builder.Services.Configure<CookieTempDataProviderOptions>(options =>
{
    options.Cookie.Name = "TempDataCookie";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Add Chapa configuration
var chapaSecretKey = builder.Configuration["Chapa:SecretKey"];
if (string.IsNullOrEmpty(chapaSecretKey))
{
    throw new ArgumentNullException(nameof(chapaSecretKey), "Chapa secret key is not configured.");
}
builder.Services.AddSingleton(new Chapa(chapaSecretKey));

// Configure ASP.NET Core Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options => {
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    
    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    
    // User settings
    options.User.RequireUniqueEmail = true;
    
    // Sign-in settings - REQUIRE EMAIL CONFIRMATION
    options.SignIn.RequireConfirmedEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Add external authentication providers
builder.Services.AddAuthentication()
    .AddGoogle(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? "";
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? "";
        options.SaveTokens = true;
    })
    .AddMicrosoftAccount(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"] ?? "";
        options.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"] ?? "";
        options.SaveTokens = true;
    });

// Configure Identity cookies
builder.Services.ConfigureApplicationCookie(options => {
    options.LoginPath = "/Auth/Login";
    options.LogoutPath = "/Auth/Logout";
    options.AccessDeniedPath = "/Auth/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("AuthorOnly", policy => policy.RequireRole("Author"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
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

// Seed the database
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<DataSeedService>();
    await seeder.SeedAsync();
}

app.Run();
