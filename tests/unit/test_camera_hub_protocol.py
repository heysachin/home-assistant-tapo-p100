import base64
import hashlib
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

from custom_components.tapo.hub.camera_hub_protocol import (
    CameraHubProtocol,
    CameraHubSession,
    ERROR_STOK_EXPIRED,
)
from custom_components.tapo.setup_helpers import (
    _is_h200_device,
    async_connect,
    async_connect_discovered_device,
)
from plugp100.api.tapo_client import TapoRequest
from plugp100.common.credentials import AuthCredential
from plugp100.devices.factory import DeviceConnectConfiguration
from plugp100.devices.hub import TapoHub
from plugp100.discovery import DiscoveredDevice, EncryptionSchema
from plugp100.errors.invalid_authentication import InvalidAuthentication


# --- Mock Server Helper ---


class MockH200HttpHandler:
    def __init__(self, username="admin", password="password123"):
        self.username = username
        self.password = password
        self.hashed_sha256 = hashlib.sha256(password.encode("utf-8")).hexdigest().upper()
        self.stok = "mock_stok_h200_test"
        self.seq = 100
        self.lsk = None
        self.ivb = None
        self.stok_expired_once = False
        self.requests_log = []

    def handle_post(self, url: str, **kwargs):
        data = kwargs.get("data")
        json_body = kwargs.get("json")

        mock_resp = MagicMock()
        mock_resp.status = 200

        # Step 1 & 2 login at base URL
        if url.endswith(":443/"):
            body = json_body or (json.loads(data) if data else {})
            params = body.get("params", {})
            cnonce = params.get("cnonce", "")

            if "digest_passwd" not in params:
                # Step 1 handshake probe
                req_user = params.get("username")
                if req_user not in (self.username, "admin"):
                    mock_resp.json = AsyncMock(
                        return_value={"error_code": -60502, "msg": "UNKNOWN_USERNAME"}
                    )
                    return mock_resp

                nonce = "TESTNONCE12345678"
                candidate = hashlib.sha256(
                    cnonce.encode("utf8")
                    + self.hashed_sha256.encode("utf8")
                    + nonce.encode("utf8")
                ).hexdigest().upper()
                device_confirm = candidate + nonce + cnonce

                mock_resp.json = AsyncMock(
                    return_value={
                        "error_code": -40413,
                        "result": {
                            "data": {
                                "nonce": nonce,
                                "device_confirm": device_confirm,
                                "encrypt_type": "3",
                            }
                        },
                    }
                )
                return mock_resp
            else:
                # Step 2 login confirmation
                nonce = "TESTNONCE12345678"
                expected_digest = hashlib.sha256(
                    self.hashed_sha256.encode("utf8")
                    + cnonce.encode("utf8")
                    + nonce.encode("utf8")
                ).hexdigest().upper()

                if params.get("digest_passwd") == expected_digest + cnonce + nonce:
                    # Calculate session keys
                    hashed_key = hashlib.sha256(
                        cnonce.encode("utf8")
                        + self.hashed_sha256.encode("utf8")
                        + nonce.encode("utf8")
                    ).hexdigest().upper()
                    self.lsk = hashlib.sha256(
                        b"lsk"
                        + cnonce.encode("utf8")
                        + nonce.encode("utf8")
                        + hashed_key.encode("utf8")
                    ).digest()[:16]
                    self.ivb = hashlib.sha256(
                        b"ivb"
                        + cnonce.encode("utf8")
                        + nonce.encode("utf8")
                        + hashed_key.encode("utf8")
                    ).digest()[:16]

                    mock_resp.json = AsyncMock(
                        return_value={
                            "error_code": 0,
                            "result": {
                                "stok": self.stok,
                                "start_seq": self.seq,
                            },
                        }
                    )
                else:
                    mock_resp.json = AsyncMock(
                        return_value={"error_code": -60500, "msg": "INVALID_PASSWORD"}
                    )
                return mock_resp

        # Encrypted request at /stok=.../ds
        if f"/stok={self.stok}/ds" in url:
            if self.stok_expired_once:
                self.stok_expired_once = False
                mock_resp.json = AsyncMock(
                    return_value={"error_code": ERROR_STOK_EXPIRED, "msg": "Token expired"}
                )
                return mock_resp

            body = json.loads(data)
            enc_req_b64 = body.get("params", {}).get("request", "")
            enc_bytes = base64.b64decode(enc_req_b64)

            # Decrypt request
            cipher = Cipher(algorithms.AES(self.lsk), modes.CBC(self.ivb))
            decryptor = cipher.decryptor()
            padded = decryptor.update(enc_bytes) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            dec_req = json.loads((unpadder.update(padded) + unpadder.finalize()).decode("utf-8"))

            method = dec_req.get("method")
            params = dec_req.get("params", {})
            self.requests_log.append((method, params))

            # Simulate device responses
            if method == "getDeviceInfo":
                resp_payload = {
                    "error_code": 0,
                    "device_info": {
                        "basic_info": {
                            "device_id": "H200_DEVICE_12345",
                            "mac": "A8-29-48-45-3A-2E",
                            "hw_ver": "1.0",
                            "sw_ver": "1.2.3 Build 240101",
                            "device_model": "H200",
                            "device_alias": "Living Room Hub",
                            "in_alarm": False,
                        }
                    },
                }
            elif method == "getChildDeviceList":
                resp_payload = {
                    "error_code": 0,
                    "childControl": {
                        "child_device_list": [
                            {
                                "device_id": "CHILD_BUTTON_1",
                                "model": "S200B",
                                "hw_ver": "1.0",
                                "fw_ver": "1.0.0",
                                "alias": "My Smart Button",
                                "status": 1,
                                "mac": "00-11-22-33-44-55",
                            }
                        ],
                        "sum": 1,
                    },
                }
            elif method == "multipleRequest":
                resp_payload = {
                    "error_code": 0,
                    "responses": [
                        {
                            "method": "controlChild",
                            "result": {
                                "responseData": {
                                    "result": {
                                        "logs": [{"id": 1, "event": "single_click"}]
                                    }
                                }
                            },
                        }
                    ],
                }
            elif method in ("play_alarm", "stop_alarm", "get_support_alarm_type_list"):
                resp_payload = {"error_code": 0, "result": {"success": True}}
            else:
                resp_payload = {"error_code": 0, "result": {}}

            # Encrypt response
            raw_resp = json.dumps(resp_payload).encode("utf-8")
            padder = padding.PKCS7(128).padder()
            padded_resp = padder.update(raw_resp) + padder.finalize()
            enc_cipher = Cipher(algorithms.AES(self.lsk), modes.CBC(self.ivb))
            encryptor = enc_cipher.encryptor()
            enc_resp = encryptor.update(padded_resp) + encryptor.finalize()
            b64_resp = base64.b64encode(enc_resp).decode("utf-8")

            mock_resp.json = AsyncMock(
                return_value={"error_code": 0, "result": {"response": b64_resp}}
            )
            return mock_resp

        mock_resp.json = AsyncMock(return_value={"error_code": -1})
        return mock_resp


class MockAiohttpSession:
    def __init__(self, handler: MockH200HttpHandler):
        self.handler = handler
        self.closed = False

    def post(self, url: str, **kwargs):
        resp = self.handler.handle_post(url, **kwargs)

        class ContextManager:
            async def __aenter__(self_inner):
                return resp

            async def __aexit__(self_inner, exc_type, exc_val, exc_tb):
                pass

        return ContextManager()

    async def close(self):
        self.closed = True


# --- Tests ---


def test_is_h200_device():
    # Model contains H200
    d1 = DiscoveredDevice(
        ip="192.168.1.5",
        mac="A8-29-48-45-3A-2E",
        device_model="H200",
        device_type="SMART.TAPOHUB",
        mgt_encrypt_schm=None,
    )
    assert _is_h200_device(d1) is True

    # Model lowercase h200
    d2 = DiscoveredDevice(
        ip="192.168.1.5",
        mac="A8-29-48-45-3A-2E",
        device_model="h200(EU)",
        device_type="SMART.TAPOHUB",
        mgt_encrypt_schm=None,
    )
    assert _is_h200_device(d2) is True

    # HTTPS supported with encrypt_type=None
    d3 = DiscoveredDevice(
        ip="192.168.1.5",
        mac="A8-29-48-45-3A-2E",
        device_model="HUB",
        device_type="SMART.TAPOHUB",
        mgt_encrypt_schm=EncryptionSchema(is_support_https=True, encrypt_type=None, http_port=80, lv=1),
    )
    assert _is_h200_device(d3) is True

    # Standard devices (P100, P110, H100 with KLAP)
    d4 = DiscoveredDevice(
        ip="192.168.1.10",
        mac="A8-29-48-45-3A-2F",
        device_model="P110",
        device_type="SMART.TAPOPLUG",
        mgt_encrypt_schm=EncryptionSchema(is_support_https=False, encrypt_type="KLAP", http_port=80, lv=2),
    )
    assert _is_h200_device(d4) is False

    d5 = DiscoveredDevice(
        ip="192.168.1.11",
        mac="A8-29-48-45-3A-30",
        device_model="H100",
        device_type="SMART.TAPOHUB",
        mgt_encrypt_schm=None,
    )
    assert _is_h200_device(d5) is False


def test_ensure_b64():
    # Plain text should be converted to base64
    assert CameraHubProtocol._ensure_b64("Living Room") == base64.b64encode(b"Living Room").decode("utf-8")
    assert CameraHubProtocol._ensure_b64("Door") == base64.b64encode(b"Door").decode("utf-8")

    # Already valid base64 should remain intact
    b64_orig = base64.b64encode("My Smart Button".encode("utf-8")).decode("utf-8")
    assert CameraHubProtocol._ensure_b64(b64_orig) == b64_orig


def test_aes_encryption_roundtrip():
    cred = AuthCredential("test@example.com", "password123")
    protocol = CameraHubProtocol(cred, "1.2.3.4", 443)
    session = CameraHubSession(
        stok="stok123",
        seq=1,
        cnonce="CNONCE",
        hashed_password="HASH",
        lsk=os.urandom(16),
        ivb=os.urandom(16),
    )

    test_message = json.dumps({"test": "hello world!", "number": 12345}).encode("utf-8")
    encrypted = protocol._encrypt(session, test_message)
    assert encrypted != test_message

    decrypted = protocol._decrypt(session, encrypted)
    assert json.loads(decrypted) == {"test": "hello world!", "number": 12345}


@pytest.mark.asyncio
async def test_camera_hub_protocol_handshake_and_get_device_info():
    handler = MockH200HttpHandler(username="test@example.com", password="password123")
    mock_session = MockAiohttpSession(handler)

    cred = AuthCredential("test@example.com", "password123")
    protocol = CameraHubProtocol(cred, "1.2.3.4", 443, http_session=mock_session)

    assert protocol.name == "CameraHub"

    # Authenticate
    auth_result = await protocol.authenticate()
    assert auth_result is True
    assert protocol._session is not None
    assert protocol._session.stok == "mock_stok_h200_test"

    # Execute get_device_info
    req = TapoRequest("get_device_info", None)
    res = (await protocol.send_request(req)).get_or_else(None)
    assert res is not None
    assert res.error_code == 0
    assert res.result["model"] == "H200"
    assert res.result["device_id"] == "H200_DEVICE_12345"
    assert res.result["mac"] == "A8-29-48-45-3A-2E"
    # Nickname was encoded to base64
    assert base64.b64decode(res.result["nickname"]).decode("utf-8") == "Living Room Hub"


@pytest.mark.asyncio
async def test_camera_hub_protocol_handshake_admin_fallback():
    # Server expects "admin", but user provided "user@example.com"
    handler = MockH200HttpHandler(username="admin", password="password123")
    mock_session = MockAiohttpSession(handler)

    cred = AuthCredential("user@example.com", "password123")
    protocol = CameraHubProtocol(cred, "1.2.3.4", 443, http_session=mock_session)

    auth_result = await protocol.authenticate()
    assert auth_result is True
    assert protocol._session is not None


@pytest.mark.asyncio
async def test_camera_hub_protocol_invalid_password():
    handler = MockH200HttpHandler(username="admin", password="correct_password")
    mock_session = MockAiohttpSession(handler)

    cred = AuthCredential("admin", "wrong_password")
    protocol = CameraHubProtocol(cred, "1.2.3.4", 443, http_session=mock_session)

    with pytest.raises(InvalidAuthentication):
        await protocol.authenticate()


@pytest.mark.asyncio
async def test_camera_hub_protocol_stok_renewal():
    handler = MockH200HttpHandler(username="admin", password="password123")
    handler.stok_expired_once = True  # Trigger expiry on next request
    mock_session = MockAiohttpSession(handler)

    cred = AuthCredential("admin", "password123")
    protocol = CameraHubProtocol(cred, "1.2.3.4", 443, http_session=mock_session)
    await protocol.authenticate()

    # Request should succeed despite expired stok because of auto-renewal
    req = TapoRequest("get_device_info", None)
    res = (await protocol.send_request(req)).get_or_else(None)
    assert res is not None
    assert res.result["model"] == "H200"


@pytest.mark.asyncio
async def test_camera_hub_protocol_child_devices():
    handler = MockH200HttpHandler(username="admin", password="password123")
    mock_session = MockAiohttpSession(handler)

    cred = AuthCredential("admin", "password123")
    protocol = CameraHubProtocol(cred, "1.2.3.4", 443, http_session=mock_session)
    await protocol.authenticate()

    # 1. component_nego
    req = TapoRequest("component_nego", None)
    res = (await protocol.send_request(req)).get_or_else(None)
    assert "component_list" in res.result
    components = [c["id"] for c in res.result["component_list"]]
    assert "control_child" in components
    assert "alarm" in components

    # 2. get_child_device_list
    req = TapoRequest("get_child_device_list", None)
    res = (await protocol.send_request(req)).get_or_else(None)
    children = res.result["child_device_list"]
    assert len(children) == 1
    child = children[0]
    assert child["device_id"] == "CHILD_BUTTON_1"
    assert child["model"] == "S200B"
    assert child["status"] == "online"
    assert base64.b64decode(child["nickname"]).decode("utf-8") == "My Smart Button"

    # 3. control_child
    control_params = MagicMock()
    control_params.device_id = "CHILD_BUTTON_1"
    control_params.requestData = MagicMock()
    control_params.requestData.method = "get_trigger_logs"
    control_params.requestData.params = None

    req = TapoRequest("control_child", control_params)
    res = (await protocol.send_request(req)).get_or_else(None)
    assert "responseData" in res.result
    assert "responses" in res.result["responseData"]["result"]

    # 4. alarm methods
    assert (await protocol.send_request(TapoRequest("play_alarm", None))).get_or_else(None).error_code == 0
    assert (await protocol.send_request(TapoRequest("stop_alarm", None))).get_or_else(None).error_code == 0
    assert (await protocol.send_request(TapoRequest("get_support_alarm_type_list", None))).get_or_else(None).error_code == 0


@pytest.mark.asyncio
async def test_async_connect_discovered_h200():
    h200_device = DiscoveredDevice(
        ip="192.168.1.5",
        mac="A8-29-48-45-3A-2E",
        device_model="H200",
        device_type="SMART.TAPOHUB",
        mgt_encrypt_schm=None,
    )
    cred = AuthCredential("admin", "password123")
    session = MagicMock()

    with patch("custom_components.tapo.setup_helpers._create_h200_hub", AsyncMock()) as mock_create:
        mock_hub = MagicMock(spec=TapoHub)
        mock_create.return_value = mock_hub

        result = await async_connect_discovered_device(h200_device, cred, session)
        assert result == mock_hub
        mock_create.assert_called_once_with("192.168.1.5", 443, cred, session)


@pytest.mark.asyncio
async def test_async_connect_manual_fallback_to_h200():
    config = DeviceConnectConfiguration(
        host="192.168.1.5",
        port=80,
        credentials=AuthCredential("admin", "password123"),
    )
    session = MagicMock()

    with patch("custom_components.tapo.setup_helpers.plugp100_connect", AsyncMock(side_effect=Exception("Port 80 unreachable"))):
        with patch("custom_components.tapo.setup_helpers._create_h200_hub", AsyncMock()) as mock_create:
            mock_hub = MagicMock(spec=TapoHub)
            mock_create.return_value = mock_hub

            result = await async_connect(config, session)
            assert result == mock_hub
            mock_create.assert_called_once_with("192.168.1.5", 443, config.credentials, session)
