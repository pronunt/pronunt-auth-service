from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import urlencode
from uuid import uuid4

import jwt
from fastapi import Depends, Request, status
from pymongo import ASCENDING
from pymongo.collection import Collection

from app.core.database import get_connection_collection
from app.core.exceptions import AppException
from app.core.http import service_request
from app.core.settings import Settings, get_settings
from app.schemas.auth import (
    AuthenticatedUser,
    GitHubCallbackResponse,
    GitHubConnectionStatusResponse,
    GitHubLoginResponse,
    GitHubRepositoryListResponse,
    GitHubRepositoryResponse,
    InternalGitHubConnectionResponse,
    LogoutResponse,
    SessionResponse,
)

SettingsDependency = Annotated[Settings, Depends(get_settings)]

class AuthService:
    def __init__(self, settings: Settings, connection_collection: Collection) -> None:
        self.settings = settings
        self.connection_collection = connection_collection
        self.connection_collection.create_index("session_id", unique=True)
        self.connection_collection.create_index("github_user_id")
        self.connection_collection.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)

    def get_login_redirect(self) -> GitHubLoginResponse:
        self._ensure_oauth_configured()
        state = self._build_state_token()
        query = urlencode(
            {
                "client_id": self.settings.github_oauth_client_id,
                "redirect_uri": self.settings.github_oauth_redirect_uri,
                "scope": self.settings.github_oauth_scopes,
                "state": state,
            }
        )
        return GitHubLoginResponse(
            redirect_url=f"{self.settings.github_oauth_authorize_url}?{query}",
            state=state,
        )

    async def complete_github_oauth(self, code: str, state: str) -> GitHubCallbackResponse:
        self._ensure_oauth_configured()
        self._decode_state_token(state)

        token_response = await service_request(
            "POST",
            self.settings.github_oauth_access_token_url,
            headers={"Accept": "application/json"},
            data={
                "client_id": self.settings.github_oauth_client_id,
                "client_secret": self.settings.github_oauth_client_secret,
                "code": code,
                "redirect_uri": self.settings.github_oauth_redirect_uri,
                "state": state,
            },
        )
        token_payload = token_response.json()
        access_token = token_payload.get("access_token")
        if not access_token:
            raise AppException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                code="github_token_exchange_failed",
                message="GitHub token exchange did not return an access token.",
                details=token_payload,
            )

        user = await self._fetch_github_user(access_token)
        expires_at = datetime.now(UTC) + timedelta(seconds=self.settings.session_ttl_seconds)
        session_id = str(uuid4())
        session_document = {
            "session_id": session_id,
            "github_user_id": user.github_user_id,
            "username": user.username,
            "name": user.name,
            "email": user.email,
            "avatar_url": str(user.avatar_url) if user.avatar_url else None,
            "access_token": access_token,
            "connected_at": datetime.now(UTC),
            "expires_at": expires_at,
        }
        self.connection_collection.update_one(
            {"session_id": session_id},
            {"$set": session_document},
            upsert=True,
        )

        session_token = self._build_session_token(session_id, user.github_user_id)
        redirect_url = (
            f"{self.settings.frontend_auth_success_url}"
            f"?status=connected&session_token={session_token}"
        )
        return GitHubCallbackResponse(
            redirect_url=redirect_url,
            session_token=session_token,
            expires_at=expires_at,
            user=user,
        )

    def get_session(self, session_token: str) -> SessionResponse:
        session = self._get_session_document(session_token)
        return self._to_session_response(session)

    def get_connection_status(self, session_token: str | None) -> GitHubConnectionStatusResponse:
        if not session_token:
            return GitHubConnectionStatusResponse(connected=False)
        try:
            session = self._get_session_document(session_token)
        except AppException:
            return GitHubConnectionStatusResponse(connected=False)
        return GitHubConnectionStatusResponse(
            connected=True,
            user=self._to_authenticated_user(session),
            expires_at=session["expires_at"],
        )

    async def list_repositories(self, session_token: str) -> GitHubRepositoryListResponse:
        session = self._get_session_document(session_token)
        response = await service_request(
            "GET",
            f"{self.settings.github_api_url}/user/repos",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {session['access_token']}",
            },
            params={
                "visibility": "all",
                "affiliation": "owner,collaborator,organization_member",
                "per_page": 100,
                "sort": "updated",
            },
        )
        items = [
            GitHubRepositoryResponse(
                id=item["id"],
                full_name=item["full_name"],
                owner=item["owner"]["login"],
                name=item["name"],
                private=item["private"],
                default_branch=item.get("default_branch", "main"),
                html_url=item["html_url"],
            )
            for item in response.json()
        ]
        return GitHubRepositoryListResponse(items=items, total=len(items))

    def get_internal_connection(self, session_token: str, internal_service_token: str) -> InternalGitHubConnectionResponse:
        self._ensure_internal_service_token(internal_service_token)
        session = self._get_session_document(session_token)
        return InternalGitHubConnectionResponse(
            session_id=session["session_id"],
            access_token=session["access_token"],
            user=self._to_authenticated_user(session),
            expires_at=session["expires_at"],
        )

    def logout(self, session_token: str) -> LogoutResponse:
        session = self._get_session_document(session_token)
        self.connection_collection.delete_one({"session_id": session["session_id"]})
        return LogoutResponse()

    def _ensure_oauth_configured(self) -> None:
        if not all(
            [
                self.settings.github_oauth_client_id,
                self.settings.github_oauth_client_secret,
                self.settings.github_oauth_redirect_uri,
                self.settings.session_jwt_secret,
            ]
        ):
            raise AppException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                code="github_oauth_not_configured",
                message="GitHub OAuth is not configured.",
            )

    def _ensure_internal_service_token(self, provided_token: str) -> None:
        if not self.settings.internal_service_token:
            raise AppException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                code="internal_service_auth_not_configured",
                message="Internal service authentication is not configured.",
            )
        if provided_token != self.settings.internal_service_token:
            raise AppException(
                status_code=status.HTTP_403_FORBIDDEN,
                code="invalid_internal_service_token",
                message="Internal service token is invalid.",
            )

    def _build_state_token(self) -> str:
        return jwt.encode(
            {
                "purpose": "github_oauth_state",
                "nonce": str(uuid4()),
                "exp": datetime.now(UTC) + timedelta(minutes=10),
                "iat": datetime.now(UTC),
            },
            self.settings.session_jwt_secret,
            algorithm="HS256",
        )

    def _decode_state_token(self, token: str) -> dict[str, Any]:
        try:
            payload = jwt.decode(
                token,
                self.settings.session_jwt_secret,
                algorithms=["HS256"],
            )
        except jwt.PyJWTError as exc:
            raise AppException(
                status_code=status.HTTP_400_BAD_REQUEST,
                code="invalid_oauth_state",
                message="GitHub OAuth state is invalid or expired.",
            ) from exc
        if payload.get("purpose") != "github_oauth_state":
            raise AppException(
                status_code=status.HTTP_400_BAD_REQUEST,
                code="invalid_oauth_state",
                message="GitHub OAuth state is invalid.",
            )
        return payload

    def _build_session_token(self, session_id: str, github_user_id: int) -> str:
        return jwt.encode(
            {
                "sub": session_id,
                "github_user_id": github_user_id,
                "iss": self.settings.session_jwt_issuer,
                "exp": datetime.now(UTC) + timedelta(seconds=self.settings.session_ttl_seconds),
                "iat": datetime.now(UTC),
            },
            self.settings.session_jwt_secret,
            algorithm="HS256",
        )

    def _decode_session_token(self, token: str) -> dict[str, Any]:
        self._ensure_oauth_configured()
        try:
            payload = jwt.decode(
                token,
                self.settings.session_jwt_secret,
                algorithms=["HS256"],
                issuer=self.settings.session_jwt_issuer,
            )
        except jwt.PyJWTError as exc:
            raise AppException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="invalid_session_token",
                message="Session token is invalid or expired.",
            ) from exc
        return payload

    def _get_session_document(self, session_token: str) -> dict[str, Any]:
        payload = self._decode_session_token(session_token)
        session = self.connection_collection.find_one({"session_id": payload["sub"]})
        if not session:
            raise AppException(
                status_code=status.HTTP_404_NOT_FOUND,
                code="session_not_found",
                message="GitHub session was not found.",
            )
        return session

    async def _fetch_github_user(self, access_token: str) -> AuthenticatedUser:
        response = await service_request(
            "GET",
            f"{self.settings.github_api_url}/user",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access_token}",
            },
        )
        user_payload = response.json()
        return AuthenticatedUser(
            github_user_id=user_payload["id"],
            username=user_payload["login"],
            name=user_payload.get("name"),
            email=user_payload.get("email"),
            avatar_url=user_payload.get("avatar_url"),
        )

    @staticmethod
    def _to_authenticated_user(document: dict[str, Any]) -> AuthenticatedUser:
        return AuthenticatedUser(
            github_user_id=document["github_user_id"],
            username=document["username"],
            name=document.get("name"),
            email=document.get("email"),
            avatar_url=document.get("avatar_url"),
        )

    def _to_session_response(self, session: dict[str, Any]) -> SessionResponse:
        return SessionResponse(
            session_id=session["session_id"],
            connected_at=session["connected_at"],
            expires_at=session["expires_at"],
            user=self._to_authenticated_user(session),
        )


def get_auth_service(settings: SettingsDependency) -> AuthService:
    return AuthService(settings=settings, connection_collection=get_connection_collection(settings))
