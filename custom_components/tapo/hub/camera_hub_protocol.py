"""Camera / Hub protocol implementation for Tapo H200 and camera-based hubs."""

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import ssl
from typing import Any, Optional

import aiohttp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from plugp100.api.protocol.tapo_protocol import TapoProtocol
from plugp100.api.requests.tapo_request import TapoRequest
from plugp100.api.transport.response import TapoResponse
from plugp100.common.credentials import AuthCredential
from plugp100.common.functional.tri import Failure, Success, Try
from plugp100.errors.invalid_authentication import InvalidAuthentication

_LOGGER = logging.getLogger(__name__)

ERROR_STOK_EXPIRED = -40401
ERROR_UNKNOWN_USER = -60502


def _create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@dataclass
class CameraHubSession:
    stok: str
    seq: int
    cnonce: str
    hashed_password: str
    lsk: bytes
    ivb: bytes


class CameraHubProtocol(TapoProtocol):
    """Protocol implementation for Tapo H200 hubs using secure camera-like transport."""

    def __init__(
        self,
        auth_credential: AuthCredential,
        host: str,
        port: int = 443,
        http_session: Optional[aiohttp.ClientSession] = None,
    ):
        self.host = host
        self.port = port
        self.credentials = auth_credential
        self.username = auth_credential.username
        self.password = auth_credential.password
        self.base_url = f"https://{self.host}:{self.port}"
        self._http_session = http_session
        self._own_session = False
        self._ssl_context = _create_ssl_context()

        self._hashed_md5_password = (
            hashlib.md5(self.password.encode("utf8")).hexdigest().upper()
        )
        self._hashed_sha256_password = (
            hashlib.sha256(self.password.encode("utf8")).hexdigest().upper()
        )

        self._session: Optional[CameraHubSession] = None
        self._lock = asyncio.Lock()
        self._hub_info_cache: Optional[dict[str, Any]] = None

    @property
    def name(self) -> str:
        return "CameraHub"

    async def authenticate(self) -> bool:
        async with self._lock:
            await self._login()
            return True

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession()
            self._own_session = True
        return self._http_session

    async def close(self):
        async with self._lock:
            self._session = None
            if self._own_session and self._http_session and not self._http_session.closed:
                await self._http_session.close()

    async def _login(self) -> CameraHubSession:
        session = await self._ensure_session()
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "requestByApp": "true",
            "Accept": "application/json",
            "User-Agent": "Tapo CameraClient Android",
        }

        # Step 1: Handshake probe with cnonce
        usernames_to_try = [self.username, "admin"] if self.username != "admin" else ["admin"]
        handshake_data = None
        selected_username = self.username
        cnonce = ""

        for candidate_user in usernames_to_try:
            cnonce = os.urandom(8).hex().upper()
            step1_payload = {
                "method": "login",
                "params": {
                    "cnonce": cnonce,
                    "encrypt_type": "3",
                    "username": candidate_user,
                },
            }
            try:
                async with session.post(
                    f"{self.base_url}/",
                    json=step1_payload,
                    headers=headers,
                    ssl=self._ssl_context,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    resp_json = await resp.json(content_type=None)
                    if (
                        resp_json.get("error_code") in (0, -40413)
                        and "result" in resp_json
                        and "data" in resp_json["result"]
                        and "nonce" in resp_json["result"]["data"]
                    ):
                        handshake_data = resp_json["result"]["data"]
                        selected_username = candidate_user
                        break
            except Exception as e:
                _LOGGER.debug("Handshake attempt with %s failed: %s", candidate_user, e)

        if not handshake_data:
            _LOGGER.error("H200 handshake probe failed for %s", self.host)
            raise InvalidAuthentication(self.host, "SMART.TAPOHUB")

        nonce = handshake_data["nonce"]
        device_confirm = handshake_data.get("device_confirm", "")

        sha256_candidate = (
            hashlib.sha256(
                cnonce.encode("utf8")
                + self._hashed_sha256_password.encode("utf8")
                + nonce.encode("utf8")
            )
            .hexdigest()
            .upper()
        )
        md5_candidate = (
            hashlib.sha256(
                cnonce.encode("utf8")
                + self._hashed_md5_password.encode("utf8")
                + nonce.encode("utf8")
            )
            .hexdigest()
            .upper()
        )
        plain_candidate = (
            hashlib.sha256(
                cnonce.encode("utf8")
                + self.password.encode("utf8")
                + nonce.encode("utf8")
            )
            .hexdigest()
            .upper()
        )

        if device_confirm == (sha256_candidate + nonce + cnonce):
            hashed_pwd = self._hashed_sha256_password
        elif device_confirm == (md5_candidate + nonce + cnonce):
            hashed_pwd = self._hashed_md5_password
        elif device_confirm == (plain_candidate + nonce + cnonce):
            hashed_pwd = self.password
        else:
            _LOGGER.error(
                "Device confirm verification failed during H200 handshake on %s",
                self.host,
            )
            raise InvalidAuthentication(self.host, "SMART.TAPOHUB")

        # Step 2: Login confirmation with digest_passwd
        digest_passwd = (
            hashlib.sha256(
                hashed_pwd.encode("utf8")
                + cnonce.encode("utf8")
                + nonce.encode("utf8")
            )
            .hexdigest()
            .upper()
        )

        step2_payload = {
            "method": "login",
            "params": {
                "cnonce": cnonce,
                "encrypt_type": "3",
                "digest_passwd": digest_passwd + cnonce + nonce,
                "username": selected_username,
            },
        }

        async with session.post(
            f"{self.base_url}/",
            json=step2_payload,
            headers=headers,
            ssl=self._ssl_context,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            login_resp = await resp.json(content_type=None)

        if (
            login_resp.get("error_code") != 0
            or "result" not in login_resp
            or "stok" not in login_resp["result"]
        ):
            _LOGGER.error("H200 login rejected credentials: %s", login_resp)
            raise InvalidAuthentication(self.host, "SMART.TAPOHUB")

        stok = login_resp["result"]["stok"]
        start_seq = login_resp["result"].get("start_seq", 0)

        # Derive AES CBC keys
        hashed_key = (
            hashlib.sha256(
                cnonce.encode("utf8")
                + hashed_pwd.encode("utf8")
                + nonce.encode("utf8")
            )
            .hexdigest()
            .upper()
        )
        lsk = hashlib.sha256(
            b"lsk" + cnonce.encode("utf8") + nonce.encode("utf8") + hashed_key.encode("utf8")
        ).digest()[:16]
        ivb = hashlib.sha256(
            b"ivb" + cnonce.encode("utf8") + nonce.encode("utf8") + hashed_key.encode("utf8")
        ).digest()[:16]

        self._session = CameraHubSession(
            stok=stok,
            seq=start_seq,
            cnonce=cnonce,
            hashed_password=hashed_pwd,
            lsk=lsk,
            ivb=ivb,
        )
        return self._session

    def _encrypt(self, session: CameraHubSession, plaintext: bytes) -> bytes:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(session.lsk), modes.CBC(session.ivb))
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def _decrypt(self, session: CameraHubSession, ciphertext: bytes) -> str:
        cipher = Cipher(algorithms.AES(session.lsk), modes.CBC(session.ivb))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        return plaintext.decode("utf-8")

    def _generate_signature(self, session: CameraHubSession, seq: int, raw_body: str) -> str:
        tag_key = (
            hashlib.sha256(
                session.hashed_password.encode("utf8") + session.cnonce.encode("utf8")
            )
            .hexdigest()
            .upper()
        )
        return (
            hashlib.sha256(
                tag_key.encode("utf8") + raw_body.encode("utf8") + str(seq).encode("utf8")
            )
            .hexdigest()
            .upper()
        )

    async def _execute_raw(self, method: str, params: Any = None) -> dict[str, Any]:
        """Send encrypted command to /stok=.../ds with automatic session refresh."""
        http_session = await self._ensure_session()

        for attempt in range(2):
            if self._session is None:
                await self._login()

            session = self._session
            req_dict = {"method": method}
            if params is not None:
                req_dict["params"] = params

            raw_req = json.dumps(req_dict).encode("utf-8")
            enc_payload = self._encrypt(session, raw_req)
            b64_enc = base64.b64encode(enc_payload).decode("utf-8")

            passthrough = {
                "method": "securePassthrough",
                "params": {"request": b64_enc},
            }
            passthrough_raw = json.dumps(passthrough)

            cur_seq = session.seq
            session.seq += 1

            signature = self._generate_signature(session, cur_seq, passthrough_raw)
            headers = {
                "Content-Type": "application/json; charset=UTF-8",
                "requestByApp": "true",
                "Accept": "application/json",
                "User-Agent": "Tapo CameraClient Android",
                "Seq": str(cur_seq),
                "Tapo_tag": signature,
            }

            url = f"{self.base_url}/stok={session.stok}/ds"
            try:
                async with http_session.post(
                    url,
                    data=passthrough_raw,
                    headers=headers,
                    ssl=self._ssl_context,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    resp_json = await resp.json(content_type=None)

                if resp_json.get("error_code") == ERROR_STOK_EXPIRED:
                    _LOGGER.debug("H200 stok expired; renewing session")
                    self._session = None
                    continue

                if "result" in resp_json and "response" in resp_json["result"]:
                    dec_bytes = base64.b64decode(resp_json["result"]["response"])
                    dec_text = self._decrypt(session, dec_bytes)
                    return json.loads(dec_text)

                return resp_json
            except Exception as e:
                if attempt == 0:
                    _LOGGER.debug("Error during H200 request execution: %s; retrying", e)
                    self._session = None
                    continue
                raise

        raise Exception("Failed to execute H200 command after session renewal")

    async def _execute_command(self, method: str, params: Any = None) -> dict[str, Any]:
        """Execute command, automatically wrapping in multipleRequest as required by modern Tapo camera firmware."""
        req_item: dict[str, Any] = {"method": method}
        if params is not None:
            req_item["params"] = params

        # Try multipleRequest first (standard for H200 / modern camera platform)
        try:
            resp = await self._execute_raw("multipleRequest", {"requests": [req_item]})
            responses = []
            if isinstance(resp, dict):
                if "responses" in resp:
                    responses = resp["responses"]
                elif "result" in resp and "responses" in resp["result"]:
                    responses = resp["result"]["responses"]

            if responses and len(responses) > 0:
                first = responses[0]
                if isinstance(first, dict):
                    if "result" in first:
                        return first["result"]
                    return first
        except Exception as e:
            _LOGGER.debug(
                "multipleRequest for %s failed (%s), falling back to direct call",
                method,
                e,
            )

        # Fallback to direct method call
        return await self._execute_raw(method, params)

    async def send_request(
        self, request: TapoRequest, retry: int = 3
    ) -> Try[TapoResponse[dict[str, Any]]]:
        """Translate TapoRequests into H200 camera-hub commands and adapt responses."""
        async with self._lock:
            try:
                res = await self._handle_request(request)
                return Success(TapoResponse(error_code=0, result=res, msg="Success"))
            except Exception as e:
                _LOGGER.exception("CameraHubProtocol request %s failed: %s", request.method, e)
                return Failure(e)

    async def _handle_request(self, request: TapoRequest) -> dict[str, Any]:
        method = request.method
        params = request.params

        # 1. Component negotiation
        if method == "component_nego":
            return {
                "component_list": [
                    {"id": "control_child", "ver_code": 1},
                    {"id": "alarm", "ver_code": 1},
                ]
            }

        # 2. Hub device info
        if method == "get_device_info":
            info_res = await self._execute_command(
                "getDeviceInfo", {"device_info": {"name": ["basic_info"]}}
            )
            basic_info = (
                info_res.get("device_info", {}).get("basic_info", {})
                if "device_info" in info_res
                else info_res.get("basic_info", info_res)
            )
            self._hub_info_cache = basic_info

            device_id = basic_info.get("device_id") or basic_info.get("mac", "")
            mac = basic_info.get("mac", "").replace(":", "-").upper()
            nickname = (
                basic_info.get("device_alias")
                or basic_info.get("alias")
                or basic_info.get("name")
                or "Tapo Hub H200"
            )
            b64_nickname = self._ensure_b64(nickname)

            return {
                "device_id": device_id,
                "hw_id": basic_info.get("hw_id", ""),
                "oem_id": basic_info.get("oem_id", ""),
                "fw_ver": basic_info.get("sw_ver") or basic_info.get("fw_ver") or "1.0.0",
                "hw_ver": basic_info.get("hw_ver", "1.0"),
                "mac": mac,
                "nickname": b64_nickname,
                "model": basic_info.get("device_model") or basic_info.get("model") or "H200",
                "type": "SMART.TAPOHUB",
                "overheated": False,
                "ip": self.host,
                "signal_level": 3,
                "rssi": 0,
                "in_alarm": basic_info.get("in_alarm", False),
            }

        # 3. Child device list
        if method == "get_child_device_list":
            start_index = getattr(params, "start_index", 0) if params else 0
            child_res = await self._execute_command(
                "getChildDeviceList", {"childControl": {"start_index": start_index}}
            )

            raw_children = []
            total_sum = 0
            if "child_device_list" in child_res:
                raw_children = child_res["child_device_list"]
                total_sum = child_res.get("sum", len(raw_children))
            elif "childControl" in child_res and "child_device_list" in child_res["childControl"]:
                raw_children = child_res["childControl"]["child_device_list"]
                total_sum = child_res["childControl"].get("sum", len(raw_children))
            elif "result" in child_res and "child_device_list" in child_res["result"]:
                raw_children = child_res["result"]["child_device_list"]
                total_sum = child_res["result"].get("sum", len(raw_children))
            elif "result" in child_res and "childControl" in child_res["result"] and "child_device_list" in child_res["result"]["childControl"]:
                raw_children = child_res["result"]["childControl"]["child_device_list"]
                total_sum = child_res["result"]["childControl"].get("sum", len(raw_children))

            parent_id = (
                self._hub_info_cache.get("device_id") if self._hub_info_cache else "H200_HUB"
            )

            adapted_children = []
            for item in raw_children:
                raw_nick = (
                    item.get("alias")
                    or item.get("nickname")
                    or item.get("name")
                    or item.get("model", "Child")
                )
                b64_nick = self._ensure_b64(raw_nick)

                child_id = item.get("device_id") or item.get("deviceId") or item.get("id")
                child_model = (
                    item.get("model")
                    or item.get("device_model")
                    or item.get("sub_type")
                    or "S200B"
                )
                child_mac = item.get("mac", "")
                adapted_children.append(
                    {
                        "device_id": child_id,
                        "hw_ver": item.get("hw_ver") or item.get("hardware_version") or "1.0",
                        "fw_ver": item.get("fw_ver") or item.get("software_version") or item.get("sw_ver") or "1.0.0",
                        "type": item.get("type") or item.get("device_type") or "SMART.TAPOBUTTON",
                        "model": child_model,
                        "mac": child_mac,
                        "nickname": b64_nick,
                        "status": "online" if item.get("status") in (1, "online", True) else "offline",
                        "parent_device_id": parent_id,
                        "rssi": item.get("rssi", 0),
                        "signal_level": item.get("signal_level", 0),
                        "at_low_battery": item.get("at_low_battery", False),
                        "lastOnboardingTimestamp": item.get("lastOnboardingTimestamp", 0),
                        "report_interval": item.get("report_interval", 16),
                    }
                )

            _LOGGER.info("H200 adapted %d child devices", len(adapted_children))

            return {
                "child_device_list": adapted_children,
                "start_index": start_index,
                "sum": total_sum or len(adapted_children),
            }

        # 4. Control child request
        if method == "control_child":
            device_id = getattr(params, "device_id", None)
            req_data = getattr(params, "requestData", None)
            inner_dict = self._serialize_tapo_request(req_data)

            child_res = await self._execute_command(
                "controlChild",
                {
                    "childControl": {
                        "device_id": device_id,
                        "request_data": inner_dict,
                    }
                },
            )

            child_output = (
                child_res.get("responseData", {}).get("result", child_res.get("result", child_res))
                if isinstance(child_res, dict)
                else child_res
            )
            return {"responseData": {"result": {"responses": [child_output]}}}

        # 5. Alarm controls
        if method == "play_alarm":
            alarm_duration = getattr(params, "alarm_duration", 30) if params else 30
            alarm_type = getattr(params, "alarm_type", "normal") if params else "normal"
            alarm_volume = getattr(params, "alarm_volume", "high") if params else "high"
            return await self._execute_command(
                "play_alarm",
                {
                    "alarm_duration": int(alarm_duration),
                    "alarm_type": str(alarm_type),
                    "alarm_volume": str(alarm_volume),
                },
            )

        if method == "stop_alarm":
            return await self._execute_command("stop_alarm")

        if method == "get_support_alarm_type_list":
            return await self._execute_command("get_support_alarm_type_list")

        # Fallback: pass-through execute
        serialized_params = self._serialize_tapo_request(params) if params else None
        return await self._execute_command(method, serialized_params)

    def _serialize_tapo_request(self, req: Any) -> Any:
        if req is None:
            return None
        if hasattr(req, "method"):
            inner = {"method": req.method}
            if req.params is not None:
                inner["params"] = self._serialize_tapo_request(req.params)
            return inner
        if hasattr(req, "requests"):
            return [self._serialize_tapo_request(r) for r in req.requests]
        if hasattr(req, "__dict__"):
            return {k: self._serialize_tapo_request(v) for k, v in req.__dict__.items()}
        return req

    @staticmethod
    def _ensure_b64(val: str) -> str:
        try:
            raw_bytes = val.encode("utf-8")
            decoded = base64.b64decode(raw_bytes, validate=True)
            if base64.b64encode(decoded) == raw_bytes:
                text = decoded.decode("utf-8")
                if text.isprintable():
                    return val
        except Exception:
            pass
        return base64.b64encode(val.encode("utf-8")).decode("utf-8")
