using System;
using Api.Data;
using Api.Identity;
using Api.Identity.Stores;
using Api.Messages.Identity;
using Api.Services;
using Api.Services.Implementations;
using Api.Services.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace WebApi.Init
{
    public class Di
    {
        public static void RegisterDi(IServiceCollection services, IConfiguration configuration)
        {
            RegisterContexts(services,configuration);
            RegisterServices(services, configuration);
        }

        private static void RegisterContexts(IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseInMemoryDatabase(
                    configuration.GetConnectionString("DefaultConnection"));
            });

            //services.AddDbContext<ApplicationDbContext>(options =>
            //{
            //    options.UseMySql(
            //        configuration.GetConnectionString("DefaultConnection"),
            //        serverDbContextOptionsBuilder =>
            //        {
            //            var minutes = (int)TimeSpan.FromMinutes(3).TotalSeconds;
            //            serverDbContextOptionsBuilder.CommandTimeout(minutes);
            //            serverDbContextOptionsBuilder.EnableRetryOnFailure();
            //            serverDbContextOptionsBuilder.MigrationsAssembly("WebApi");
            //        });
            //});

            //services.AddDbContext<ApplicationDbContext>(options =>
            //{
            //    options.UseSqlServer(
            //        configuration.GetConnectionString("DefaultConnection"),
            //        serverDbContextOptionsBuilder =>
            //        {
            //            var minutes = (int)TimeSpan.FromMinutes(3).TotalSeconds;
            //            serverDbContextOptionsBuilder.CommandTimeout(minutes);
            //            serverDbContextOptionsBuilder.EnableRetryOnFailure();
            //            serverDbContextOptionsBuilder.MigrationsAssembly("WebApi");
            //        });
            //});
        }

        private static void RegisterServices(IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<BearerTokensOptions>(options => configuration.GetSection("BearerTokens").Bind(options));
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.TryAddTransient<IHttpContextAccessor, HttpContextAccessor>();
            services.AddTransient<IUserStore<User>, UserStoreService>();
            services.AddTransient<IRoleStore<Role>, RoleStoreService>();
            services.AddTransient<IUserRoleStore<User>, UserStoreService>();
            services.AddTransient<ITokenStoreService, TokenStoreService>();
            services.AddTransient<ISecurityService, SecurityService>();
            services.AddTransient<IAntiForgeryCookieService, AntiForgeryCookieService>();
            services.AddTransient<ITokenValidatorService, TokenValidatorService>();
            services.AddTransient<ILastLoggedIn, UserStoreService>();
        }
    }
}
