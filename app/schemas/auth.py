from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl


class GitHubLoginResponse(BaseModel):
    redirect_url: HttpUrl | str
    state: str


class AuthenticatedUser(BaseModel):
    github_user_id: int
    username: str
    name: str | None = None
    email: str | None = None
    avatar_url: HttpUrl | str | None = None


class GitHubCallbackResponse(BaseModel):
    status: str = "connected"
    redirect_url: HttpUrl | str
    session_token: str
    expires_at: datetime
    user: AuthenticatedUser


class SessionResponse(BaseModel):
    session_id: str
    connected_at: datetime
    expires_at: datetime
    user: AuthenticatedUser


class GitHubRepositoryResponse(BaseModel):
    id: int
    full_name: str
    owner: str
    name: str
    private: bool
    default_branch: str
    html_url: HttpUrl | str
    installation_hint: str = Field(default="oauth")


class GitHubRepositoryListResponse(BaseModel):
    items: list[GitHubRepositoryResponse]
    total: int


class GitHubConnectionStatusResponse(BaseModel):
    connected: bool
    user: AuthenticatedUser | None = None
    expires_at: datetime | None = None


class LogoutResponse(BaseModel):
    status: str = "disconnected"


class InternalGitHubConnectionResponse(BaseModel):
    session_id: str
    access_token: str
    user: AuthenticatedUser
    expires_at: datetime


class InternalSessionResponse(BaseModel):
    session_id: str
    subject: str
    username: str
    roles: list[str]
    user: AuthenticatedUser
    expires_at: datetime
