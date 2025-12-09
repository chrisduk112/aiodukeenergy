"""
Duke Energy API Client - Updated for OAuth Authentication (December 2025)

This update implements the new OpenID Connect / Auth0 authentication flow
that Duke Energy migrated to in November 2025.

Changes from original v0.3.0:
1. New CLIENT_ID and CLIENT_SECRET from app v7.0
2. New OAuth flow with PKCE support
3. New token endpoint at /login/auth-token
4. Support for id_token exchange
5. Added refresh token support
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse

import aiohttp
import yarl

# API Base URLs
_API_BASE_URL = yarl.URL("https://api-v2.cma.duke-energy.app")
_AUTH_BASE_URL = yarl.URL("https://login.duke-energy.com")

# NEW Client ID and Secret from Duke Energy iOS app v7.0 (December 2025)
# These were extracted from the app by community members
_CLIENT_ID = "rNWiQDtNZBXy8kS1oLrL2PkqsEgFsL41Cb3RL0q26WpamV33"
_CLIENT_SECRET = "K8Itxznw6ZgvRuyK4m6Im9t5SOyrsvZjZrz1uzUJUgjg0ZFGnPnmzaRuWKfT51fV"  # noqa: S105

# Redirect URI used by the mobile app
_REDIRECT_URI = "cma-prod://login.duke-energy.com/android/com.dukeenergy.customerapp.release/callback"

# Token Auth header (Base64 encoded CLIENT_ID:CLIENT_SECRET)
_TOKEN_AUTH = base64.b64encode(f"{_CLIENT_ID}:{_CLIENT_SECRET}".encode()).decode()

_DATE_FORMAT = "%m/%d/%Y"
_LOGGER = logging.getLogger(__name__)


class DukeEnergyError(Exception):
    """Base exception for Duke Energy errors."""


class DukeEnergyAuthError(DukeEnergyError):
    """Exception for Duke Energy authentication errors."""


class DukeEnergy:
    """Duke Energy API client with OAuth support."""

    def __init__(
        self,
        username: str,
        password: str,
        session: aiohttp.ClientSession | None = None,
        timeout: int = 30,
    ) -> None:
        """Initialize the Duke Energy API client."""
        self.username = username
        self.password = password
        self.session = session or aiohttp.ClientSession()
        self._created_session = not session
        self.timeout = timeout
        self._auth: dict[str, Any] | None = None
        self._accounts: dict[str, Any] | None = None
        self._meters: dict[str, Any] | None = None
        self._code_verifier: str | None = None

    @property
    def internal_user_id(self) -> str | None:
        """Get the internal user ID from auth response."""
        return self._auth.get("internalUserID") if self._auth else None

    @property
    def email(self) -> str | None:
        """Get the email from auth response."""
        return self._auth.get("loginEmailAddress") if self._auth else None

    async def close(self) -> None:
        """Close the Duke Energy API client."""
        if self._created_session:
            await self.session.close()

    def _generate_pkce_pair(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge pair."""
        # Generate a random code verifier (43-128 characters)
        code_verifier = secrets.token_urlsafe(32)

        # Create code challenge using S256 method
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")

        return code_verifier, code_challenge

    async def authenticate(self) -> dict[str, Any]:
        """
        Authenticate with Duke Energy using OAuth flow.

        This implements the new OpenID Connect flow that Duke Energy
        uses as of November 2025.
        """
        _LOGGER.debug("Starting OAuth authentication flow")

        # Step 1: Generate PKCE pair
        self._code_verifier, code_challenge = self._generate_pkce_pair()
        state = secrets.token_urlsafe(16)

        # Step 2: Get authorization URL and initiate flow
        auth_params = {
            "client_id": _CLIENT_ID,
            "redirect_uri": _REDIRECT_URI,
            "response_type": "code",
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }

        authorize_url = _AUTH_BASE_URL.joinpath("authorize").with_query(auth_params)
        _LOGGER.debug("Authorization URL: %s", authorize_url)

        # Step 3: Follow redirects to get to the login form
        response = await self.session.get(
            authorize_url,
            allow_redirects=True,
            timeout=self.timeout,
        )

        _LOGGER.debug("Authorize response status: %s", response.status)
        if response.status != 200:
            raise DukeEnergyAuthError(f"Failed to initiate OAuth: {response.status}")

        # Get the login page HTML to extract the state token
        login_html = await response.text()
        final_url = str(response.url)
        _LOGGER.debug("Redirected to: %s", final_url)

        # Extract the state token from the login page
        # Auth0 typically includes this in a hidden form field
        state_match = re.search(r'name="state"\s+value="([^"]+)"', login_html)
        if not state_match:
            # Try alternative pattern
            state_match = re.search(r'name=["\']state["\']\s+value=["\']([^"\']+)["\']', login_html)

        if not state_match:
            _LOGGER.debug("Login HTML snippet: %s", login_html[:2000])
            raise DukeEnergyAuthError("Could not find state token in login page")

        login_state = state_match.group(1)
        _LOGGER.debug("Found login state token")

        # Step 4: Submit login credentials
        login_url = _AUTH_BASE_URL.joinpath("u", "login", "password")
        login_data = {
            "state": login_state,
            "username": self.username,
            "password": self.password,
            "action": "default",
        }

        _LOGGER.debug("Submitting login to: %s", login_url)

        response = await self.session.post(
            login_url,
            data=login_data,
            allow_redirects=False,  # We need to catch the redirect
            timeout=self.timeout,
        )

        _LOGGER.debug("Login response status: %s", response.status)

        # Should get a redirect (302) on success
        if response.status not in (302, 303):
            error_html = await response.text()
            if "invalid" in error_html.lower() or "incorrect" in error_html.lower():
                raise DukeEnergyAuthError("Invalid username or password")
            raise DukeEnergyAuthError(f"Login failed with status {response.status}")

        # Get the redirect URL which should contain the authorization code
        redirect_location = response.headers.get("Location", "")
        _LOGGER.debug("Login redirect to: %s", redirect_location)

        # Step 5: Follow redirect chain to get authorization code
        authorization_code = await self._follow_redirects_for_code(redirect_location)

        if not authorization_code:
            raise DukeEnergyAuthError("Failed to obtain authorization code")

        # Step 6: Exchange authorization code for OAuth tokens
        _LOGGER.debug("Exchanging authorization code for tokens")

        token_url = _AUTH_BASE_URL.joinpath("oauth", "token")
        token_data = {
            "client_id": _CLIENT_ID,
            "code": authorization_code,
            "code_verifier": self._code_verifier,
            "grant_type": "authorization_code",
            "redirect_uri": _REDIRECT_URI,
        }

        response = await self.session.post(
            token_url,
            json=token_data,
            timeout=self.timeout,
        )

        _LOGGER.debug("Token exchange response status: %s", response.status)
        if response.status != 200:
            error_text = await response.text()
            raise DukeEnergyAuthError(f"Token exchange failed: {error_text}")

        oauth_tokens = await response.json()
        _LOGGER.debug("Got OAuth tokens (access, id, refresh)")

        # Step 7: Exchange id_token for Duke Energy API token
        _LOGGER.debug("Exchanging id_token for Duke Energy API token")

        api_token_url = _API_BASE_URL.joinpath("login", "auth-token")

        response = await self.session.post(
            api_token_url,
            headers={"Authorization": f"Basic {_TOKEN_AUTH}"},
            json={"idToken": oauth_tokens["id_token"]},
            timeout=self.timeout,
        )

        _LOGGER.debug("API token response status: %s", response.status)
        if response.status != 200:
            error_text = await response.text()
            raise DukeEnergyAuthError(f"API token exchange failed: {error_text}")

        api_auth = await response.json()

        # Store auth info
        self._auth = {
            **api_auth,
            "issued_at": str(int(datetime.now(timezone.utc).timestamp())),
            "expires_in": api_auth.get("expires_in", 3600),
            "oauth_refresh_token": oauth_tokens.get("refresh_token"),
        }

        _LOGGER.info("Successfully authenticated as %s", self.email)
        return self._auth

    async def _follow_redirects_for_code(self, initial_url: str) -> str | None:
        """Follow redirect chain to extract authorization code."""
        current_url = initial_url

        for _ in range(10):  # Max 10 redirects
            if not current_url:
                break

            # Check if this is the callback URL with the code
            if current_url.startswith(_REDIRECT_URI):
                parsed = urlparse(current_url)
                query_params = parse_qs(parsed.query)
                if "code" in query_params:
                    _LOGGER.debug("Got authorization code")
                    return query_params["code"][0]

            # If it's a full URL starting with http, follow it
            if current_url.startswith("http"):
                url = current_url
            else:
                # Relative URL, build full URL
                url = str(_AUTH_BASE_URL.joinpath(current_url.lstrip("/")))

            response = await self.session.get(
                url,
                allow_redirects=False,
                timeout=self.timeout,
            )
            current_url = response.headers.get("Location", "")

        return None

    async def refresh_token(self) -> dict[str, Any]:
        """Refresh the OAuth tokens using the refresh token."""
        if not self._auth or not self._auth.get("oauth_refresh_token"):
            raise DukeEnergyAuthError("No refresh token available")

        _LOGGER.debug("Refreshing OAuth token")

        token_url = _AUTH_BASE_URL.joinpath("oauth", "token")
        token_data = {
            "client_id": _CLIENT_ID,
            "refresh_token": self._auth["oauth_refresh_token"],
            "grant_type": "refresh_token",
        }

        response = await self.session.post(
            token_url,
            json=token_data,
            timeout=self.timeout,
        )

        if response.status != 200:
            error_text = await response.text()
            raise DukeEnergyAuthError(f"Token refresh failed: {error_text}")

        oauth_tokens = await response.json()

        # Exchange new id_token for Duke Energy API token
        api_token_url = _API_BASE_URL.joinpath("login", "auth-token")

        response = await self.session.post(
            api_token_url,
            headers={"Authorization": f"Basic {_TOKEN_AUTH}"},
            json={"idToken": oauth_tokens["id_token"]},
            timeout=self.timeout,
        )

        if response.status != 200:
            error_text = await response.text()
            raise DukeEnergyAuthError(f"API token exchange failed: {error_text}")

        api_auth = await response.json()

        self._auth = {
            **api_auth,
            "issued_at": str(int(datetime.now(timezone.utc).timestamp())),
            "expires_in": api_auth.get("expires_in", 3600),
            "oauth_refresh_token": oauth_tokens.get(
                "refresh_token", self._auth.get("oauth_refresh_token")
            ),
        }

        return self._auth

    async def get_accounts(self, fresh: bool = False) -> dict[str, dict[str, Any]]:
        """
        Get account details from Duke Energy.

        :param fresh: Whether to fetch fresh data.
        """
        if self._accounts and not fresh:
            return self._accounts

        if not self.email or not self.internal_user_id:
            await self._validate_auth()

        account_list = await self._get_json(
            _API_BASE_URL.joinpath("account-list"),
            {
                "email": self.email,
                "internalUserID": self.internal_user_id,
                "fetchFreshData": "true",
            },
        )

        accounts = {}
        for account in account_list["accounts"]:
            details = await self._get_json(
                _API_BASE_URL.joinpath("account-details-v2"),
                {
                    "email": self.email,
                    "srcSysCd": account["srcSysCd"],
                    "srcAcctId": account["srcAcctId"],
                    "primaryBpNumber": account["primaryBpNumber"],
                    "relatedBpNumber": account_list["relatedBpNumber"],
                },
            )
            accounts[account["accountNumber"]] = {
                **account,
                "details": details,
            }

        self._accounts = accounts
        return self._accounts

    async def get_meters(self, fresh: bool = False) -> dict[str, dict[str, Any]]:
        """
        Get meter details from Duke Energy.

        :param fresh: Whether to fetch fresh data.
        """
        if self._meters and not fresh:
            return self._meters

        if not self._accounts:
            await self.get_accounts(fresh)

        meters = {}
        for account in self._accounts.values() if self._accounts else []:
            for meter in account["details"]["meterInfo"]:
                # set meter info and add account without details
                meters[meter["serialNum"]] = {
                    **meter,
                    "account": {k: v for k, v in account.items() if k != "details"},
                }

        self._meters = meters
        return self._meters

    async def get_energy_usage(
        self,
        serial_number: str,
        interval: Literal["HOURLY", "DAILY"],
        period: Literal["DAY", "WEEK", "BILLINGCYCLE"],
        start_date: datetime,
        end_date: datetime,
        include_temperature: bool = True,
    ) -> dict[str, Any]:
        """
        Get energy usage from Duke Energy.

        :param serial_number: The serial number of the meter.
        :param interval: The interval.
        :param period: The period.
        :param start_date: The start date.
        :param end_date: The end date.
        :param include_temperature: Whether to include temperature.
        """
        if not self._meters:
            await self.get_meters()

        meter = self._meters.get(serial_number) if self._meters else None
        if meter is None:
            msg = f"Meter {serial_number} not found"
            raise ValueError(msg)

        result = await self._get_json(
            _API_BASE_URL.joinpath("account", "usage", "graph"),
            {
                "srcSysCd": meter["account"]["srcSysCd"],
                "srcAcctId": meter["account"]["srcAcctId"],
                "srcAcctId2": meter["account"]["srcAcctId2"] or "",
                "meterSerialNumber": meter["serialNum"],
                "serviceType": meter["serviceType"],
                "intervalFrequency": interval,
                "periodType": period,
                "date": start_date.strftime(_DATE_FORMAT),
                "includeWeatherData": "true" if include_temperature else "false",
                "agrmtStartDt": datetime.strptime(
                    meter["agreementActiveDate"], "%Y-%m-%d"
                ).strftime(_DATE_FORMAT),
                "agrmtEndDt": datetime.strptime(
                    meter["agreementEndDate"], "%Y-%m-%d"
                ).strftime(_DATE_FORMAT),
                "meterCertDt": datetime.strptime(
                    meter["meterCertificationDate"], "%Y-%m-%d"
                ).strftime(_DATE_FORMAT),
                "startDate": start_date.strftime(_DATE_FORMAT),
                "endDate": end_date.strftime(_DATE_FORMAT),
                "zipCode": meter["account"]["serviceAddressParsed"]["zipCode"],
                "showYear": "true",
            },
        )

        # Process usage data
        usage_array = result["usageArray"]
        usage_len = len(usage_array)
        num_expected_values = (end_date - start_date).days + 1

        temp = [
            usage_array[i]["temperatureAvg"]
            for i in range(min(num_expected_values, usage_len))
        ]
        temp_len = len(temp)

        if interval == "HOURLY":
            num_expected_values = num_expected_values * 24
            temp = [t for t in temp for _ in range(24)]
            temp_len = len(temp)

        num_values = max(usage_len, num_expected_values)
        data = {}
        missing = []
        offset = 0
        duplicates = 0

        for i in range(num_values):
            delta = (
                timedelta(hours=i - duplicates)
                if interval == "HOURLY"
                else timedelta(days=i)
            )
            date = start_date + delta
            n = i - offset

            if n >= usage_len:
                missing.append(date)
                continue

            expected_series = (
                date.strftime("%I %p")
                if interval == "HOURLY"
                else date.strftime("%m/%d/%Y")
            )

            # Skip duplicate dates
            if n > 0 and usage_array[n]["date"] == usage_array[n - 1]["date"]:
                duplicates += 1
                continue

            # Skip missing dates
            if usage_array[n]["date"] != expected_series:
                missing.append(date)
                offset += 1
                continue

            if not float(usage_array[n]["usage"]) > 0:
                missing.append(date)
                continue

            data[date] = {
                "energy": float(usage_array[n]["usage"]),
                "temperature": temp[n] if n < temp_len else None,
            }

        return {"data": data, "missing": missing}

    async def _get_json(
        self, url: yarl.URL, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Get JSON from the Duke Energy API."""
        await self._validate_auth()

        if not self._auth:
            msg = "Authentication failed"
            raise ValueError(msg)

        _LOGGER.debug("Calling %s with params: %s", url, params)

        response = await self.session.get(
            url,
            headers={"Authorization": f"Bearer {self._auth['access_token']}"},
            params=params or {},
            timeout=self.timeout,
        )

        _LOGGER.debug("Response from %s: %s", url, response.status)
        response.raise_for_status()
        json_data = await response.json()
        _LOGGER.debug("JSON from %s: %s", url, json_data)
        return json_data

    async def _validate_auth(self) -> None:
        """Validate the authentication tokens and fetch new ones if necessary."""
        if self._auth:
            issued_at = datetime.fromtimestamp(
                int(self._auth["issued_at"]), timezone.utc
            )
            expires_in = int(self._auth["expires_in"])
            expiry = issued_at + timedelta(seconds=expires_in)

            # Add 5 minute buffer before expiry
            if expiry > datetime.now(timezone.utc) + timedelta(minutes=5):
                return

            # Try to refresh if we have a refresh token
            if self._auth.get("oauth_refresh_token"):
                try:
                    await self.refresh_token()
                    return
                except DukeEnergyAuthError:
                    _LOGGER.warning("Token refresh failed, re-authenticating")

        await self.authenticate()
