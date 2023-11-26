FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["IdentityServer.OpenIddict/IdentityServer.OpenIddict.csproj", "IdentityServer.OpenIddict/"]
RUN dotnet restore "IdentityServer.OpenIddict/IdentityServer.OpenIddict.csproj"
COPY . .
WORKDIR "/src/IdentityServer.OpenIddict"
RUN dotnet build "IdentityServer.OpenIddict.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "IdentityServer.OpenIddict.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "IdentityServer.OpenIddict.dll"]
