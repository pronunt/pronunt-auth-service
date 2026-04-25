from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, status as http_status
from fastapi.responses import RedirectResponse

from app.core.exceptions import AppException
from app.schemas.auth import (
    GitHubConnectionStatusResponse,
    GitHubLoginResponse,
    GitHubRepositoryListResponse,
    InternalGitHubConnectionResponse,
    LogoutResponse,
    SessionResponse,
)
from app.services.auth import AuthService, get_auth_service

router = APIRouter(tags=["auth"])
AuthServiceDependency = Annotated[AuthService, Depends(get_auth_service)]
CodeQuery = Annotated[str, Query(..., min_length=1)]
StateQuery = Annotated[str, Query(..., min_length=1)]


def get_session_token(request: Request) -> str:
    authorization = request.headers.get("Authorization")
    if not authorization:
        raise AppException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            code="missing_session_token",
            message="Session token is required.",
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AppException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            code="invalid_session_header",
            message="Authorization header must use Bearer token format.",
        )
    return token


@router.get("/github/login")
def github_login(service: AuthServiceDependency) -> GitHubLoginResponse:
    return service.get_login_redirect()


@router.get("/github/callback")
async def github_callback(
    service: AuthServiceDependency,
    code: CodeQuery,
    state: StateQuery,
) -> RedirectResponse:
    callback_response = await service.complete_github_oauth(code, state)
    return RedirectResponse(url=str(callback_response.redirect_url), status_code=http_status.HTTP_302_FOUND)


@router.get("/me")
def me(request: Request, service: AuthServiceDependency) -> SessionResponse:
    return service.get_session(get_session_token(request))


@router.get("/status")
def status(request: Request, service: AuthServiceDependency) -> GitHubConnectionStatusResponse:
    authorization = request.headers.get("Authorization")
    if not authorization:
        return service.get_connection_status(None)
    return service.get_connection_status(get_session_token(request))


@router.get("/github/repos")
async def github_repositories(request: Request, service: AuthServiceDependency) -> GitHubRepositoryListResponse:
    return await service.list_repositories(get_session_token(request))


@router.get("/internal/github-connection")
def internal_github_connection(
    request: Request,
    x_internal_service_token: Annotated[str, Header(alias="X-Internal-Service-Token")],
    service: AuthServiceDependency,
) -> InternalGitHubConnectionResponse:
    return service.get_internal_connection(get_session_token(request), x_internal_service_token)


@router.post("/logout")
def logout(request: Request, service: AuthServiceDependency) -> LogoutResponse:
    return service.logout(get_session_token(request))
