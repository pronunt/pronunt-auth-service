from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "pronunt-service"
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000

    log_level: str = "INFO"
    log_use_colors: bool = True

    request_id_header: str = "X-Request-ID"
    http_timeout_seconds: float = 10.0
    mongodb_uri: str = "mongodb://mongodb:27017"
    mongodb_database: str = "pronunt"
    mongodb_connection_collection: str = "auth_github_connections"

    auth_enabled: bool = False
    allow_unsafe_dev_auth: bool = True
    keycloak_issuer: str | None = None
    keycloak_audience: str = "pronunt-api"
    keycloak_jwks_url: str | None = None
    github_api_url: str = "https://api.github.com"
    github_oauth_authorize_url: str = "https://github.com/login/oauth/authorize"
    github_oauth_access_token_url: str = "https://github.com/login/oauth/access_token"
    github_oauth_client_id: str | None = None
    github_oauth_client_secret: str | None = None
    github_oauth_redirect_uri: str | None = None
    github_oauth_scopes: str = "read:user,user:email,repo,read:org"
    frontend_auth_success_url: str = "http://localhost:3000/connect"
    frontend_auth_failure_url: str = "http://localhost:3000/connect"
    session_jwt_secret: str | None = None
    session_jwt_issuer: str = "pronunt-auth-service"
    session_ttl_seconds: int = 604800
    internal_service_token: str | None = None

    def validate_runtime(self) -> None:
        errors: list[str] = []
        secure_envs = {"test", "testing", "stage", "staging", "prod", "production"}

        if self.http_timeout_seconds <= 0:
            errors.append("HTTP_TIMEOUT_SECONDS must be greater than 0.")
        if self.session_ttl_seconds <= 0:
            errors.append("SESSION_TTL_SECONDS must be greater than 0.")

        if self.auth_enabled:
            if not self.keycloak_issuer:
                errors.append("KEYCLOAK_ISSUER is required when AUTH_ENABLED=true.")
            if not self.keycloak_jwks_url:
                errors.append("KEYCLOAK_JWKS_URL is required when AUTH_ENABLED=true.")

        oauth_values = [
            self.github_oauth_client_id,
            self.github_oauth_client_secret,
            self.github_oauth_redirect_uri,
            self.session_jwt_secret,
            self.internal_service_token,
        ]
        if any(value for value in oauth_values) and not all(value for value in oauth_values):
            errors.append(
                "GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET, "
                "GITHUB_OAUTH_REDIRECT_URI, SESSION_JWT_SECRET, and INTERNAL_SERVICE_TOKEN "
                "must be configured together."
            )

        if self.app_env.lower() in secure_envs and self.allow_unsafe_dev_auth:
            errors.append("ALLOW_UNSAFE_DEV_AUTH must be false outside local development.")

        if errors:
            raise ValueError(" ".join(errors))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
