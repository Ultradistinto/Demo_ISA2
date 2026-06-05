# syntax=docker/dockerfile:1.7

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY SiemDemo.Api.csproj ./
RUN dotnet restore SiemDemo.Api.csproj
COPY . .
RUN dotnet publish SiemDemo.Api.csproj -c Release -o /app /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
# curl para el healthcheck del docker-compose (no es estrictamente necesario en runtime)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app .

# Kestrel escucha en 5080 sobre 0.0.0.0 (configurado en appsettings.json).
EXPOSE 5080
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_URLS=http://0.0.0.0:5080 \
    DOTNET_RUNNING_IN_CONTAINER=true

ENTRYPOINT ["dotnet", "SiemDemo.Api.dll"]
