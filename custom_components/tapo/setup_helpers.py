import logging
from typing import Optional

import aiohttp
from aiohttp import ClientSession
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from plugp100.api.tapo_client import TapoClient
from plugp100.common.credentials import AuthCredential
from plugp100.devices.base import TapoDevice
from plugp100.devices.factory import DeviceConnectConfiguration
from plugp100.devices.factory import connect as plugp100_connect
from plugp100.devices.hub import TapoHub
from plugp100.discovery import DiscoveredDevice
from plugp100.discovery import connect_discovered_device as plugp100_connect_discovered_device
from plugp100.errors.invalid_authentication import InvalidAuthentication
from plugp100.errors.protocol_guess import (
    HostUnreachableError,
    ProtocolDetectionTimeoutError,
    UnsupportedProtocolError,
)

from custom_components.tapo.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from custom_components.tapo.hub.camera_hub_protocol import CameraHubProtocol

_LOGGER = logging.getLogger(__name__)


def create_aiohttp_session(hass: HomeAssistant) -> ClientSession:
    session = async_create_clientsession(
        hass, cookie_jar=aiohttp.CookieJar(unsafe=True, quote_cookie=False)
    )
    return session


def create_device_config(config: ConfigEntry) -> DeviceConnectConfiguration:
    credential = (
        AuthCredential(
            config.data.get(CONF_USERNAME),
            config.data.get(CONF_PASSWORD),
        )
        if config.data.get(CONF_USERNAME) is not None
        else None
    )
    host, port = get_host_port(config.data.get(CONF_HOST))
    return DeviceConnectConfiguration(host=host, port=port, credentials=credential)


def get_host_port(host_user_input: str) -> tuple[str, int]:
    if ":" in host_user_input:
        parts = host_user_input.split(":", 1)
        return parts[0], int(parts[1])
    return host_user_input, 80


async def async_connect(
    config: DeviceConnectConfiguration,
    session: ClientSession,
) -> TapoDevice:
    """Connect to a Tapo device with transparent fallback to CameraHubProtocol on port 443 for H200 hubs."""
    if config.port == 443:
        try:
            return await _create_h200_hub(config.host, 443, config.credentials, session)
        except Exception as hub_err:
            _LOGGER.error(
                "CameraHubProtocol on %s:443 failed: %s",
                config.host,
                hub_err,
                exc_info=True,
            )
            raise hub_err

    original_error = None
    try:
        return await plugp100_connect(config=config, session=session)
    except (
        HostUnreachableError,
        ProtocolDetectionTimeoutError,
        UnsupportedProtocolError,
        Exception,
    ) as e:
        original_error = e

    _LOGGER.info(
        "Standard connection failed on %s:%s (%s), attempting CameraHubProtocol on port 443",
        config.host,
        config.port,
        original_error,
    )
    try:
        return await _create_h200_hub(config.host, 443, config.credentials, session)
    except Exception as hub_err:
        _LOGGER.error(
            "CameraHubProtocol attempt on %s:443 failed: %s",
            config.host,
            hub_err,
            exc_info=True,
        )
        if isinstance(hub_err, InvalidAuthentication):
            raise hub_err
        if original_error is not None:
            raise original_error from hub_err
        raise hub_err


async def async_connect_discovered_device(
    discovered_device: DiscoveredDevice,
    credentials: Optional[AuthCredential],
    session: ClientSession,
) -> TapoDevice:
    """Connect to a discovered device with support for H200 hubs."""
    if _is_h200_device(discovered_device):
        _LOGGER.info("Detected Tapo H200 hub via discovery, using CameraHubProtocol")
        return await _create_h200_hub(
            discovered_device.ip, 443, credentials, session
        )
    try:
        return await plugp100_connect_discovered_device(
            discovered_device=discovered_device,
            credentials=credentials,
            session=session,
        )
    except Exception as e:
        _LOGGER.debug(
            "Standard discovery connect failed (%s), attempting CameraHubProtocol fallback",
            e,
        )
        return await _create_h200_hub(
            discovered_device.ip, 443, credentials, session
        )


def _is_h200_device(device: DiscoveredDevice) -> bool:
    model = (device.device_model or "").upper()
    if "H200" in model:
        return True
    if device.mgt_encrypt_schm and device.mgt_encrypt_schm.is_support_https:
        if device.mgt_encrypt_schm.encrypt_type is None:
            return True
    return False


async def _create_h200_hub(
    host: str,
    port: int,
    credentials: Optional[AuthCredential],
    session: ClientSession,
) -> TapoHub:
    if credentials is None:
        raise InvalidAuthentication(host, "SMART.TAPOHUB")
    protocol = CameraHubProtocol(
        auth_credential=credentials,
        host=host,
        port=port,
        http_session=session,
    )
    await protocol.authenticate()
    client = TapoClient(credentials, f"https://{host}:{port}/app", protocol, session)
    return TapoHub(host, port, client)
