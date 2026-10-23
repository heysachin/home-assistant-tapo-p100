"""Camera / Hub protocol implementation for Tapo H200 and camera-based hubs."""

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import ssl
import time
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
        self._children_cache: dict[str, dict[str, Any]] = {}
        self._children_cache_timestamp: float = 0.0

    @property
    def name(self) -> str:
        return "CameraHub"

    @property
    def http_session(self) -> Optional[aiohttp.ClientSession]:
        return self._http_session

    async def authenticate(self) -> bool:
        async with self._lock:
            await self._login()
            return True

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._http_session is None or self._http_session.closed:
            connector = aiohttp.TCPConnector(
                limit=2,
                limit_per_host=1,
                keepalive_timeout=30,
                ssl=False,
            )
            self._http_session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=5, connect=2),
            )
            self._own_session = True
        return self._http_session

    async def close(self):
        async with self._lock:
            self._session = None
            if self._own_session and self._http_session and not self._http_session.closed:
                await self._http_session.close()
                self._http_session = None

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

    async def _refresh_children_cache(self) -> None:
        """Fetch latest child devices from H200 and update internal cache."""
        try:
            child_res = await self._execute_command(
                "getChildDeviceList", {"childControl": {"start_index": 0}}
            )

            raw_children = []
            if "child_device_list" in child_res:
                raw_children = child_res["child_device_list"]
            elif "childControl" in child_res and "child_device_list" in child_res["childControl"]:
                raw_children = child_res["childControl"]["child_device_list"]
            elif "result" in child_res and "child_device_list" in child_res["result"]:
                raw_children = child_res["result"]["child_device_list"]
            elif (
                "result" in child_res
                and "childControl" in child_res["result"]
                and "child_device_list" in child_res["result"]["childControl"]
            ):
                raw_children = child_res["result"]["childControl"]["child_device_list"]

            parent_id = (
                self._hub_info_cache.get("device_id") if self._hub_info_cache else "H200_HUB"
            )

            for item in raw_children:
                child_id = item.get("device_id") or item.get("deviceId") or item.get("id")
                if not child_id:
                    continue
                raw_nick = (
                    item.get("alias")
                    or item.get("nickname")
                    or item.get("name")
                    or item.get("model", "Child")
                )
                b64_nick = self._ensure_b64(raw_nick)

                child_model = (
                    item.get("model")
                    or item.get("device_model")
                    or item.get("sub_type")
                    or "S200B"
                )
                child_mac = item.get("mac", "")

                self._children_cache[child_id] = {
                    "device_id": child_id,
                    "hw_id": item.get("hw_id") or item.get("hardware_id") or "1.0",
                    "oem_id": item.get("oem_id") or "1.0",
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
                    "battery_percentage": item.get("battery_percentage", -1),
                    "lastOnboardingTimestamp": item.get("lastOnboardingTimestamp", 0),
                    "report_interval": item.get("report_interval", 16),
                }

            self._children_cache_timestamp = time.monotonic()
            _LOGGER.info("H200 refreshed %d child devices", len(self._children_cache))
        except Exception as e:
            _LOGGER.debug("Failed to refresh H200 children cache: %s", e)

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
            await self._refresh_children_cache()
            children = list(self._children_cache.values())
            return {
                "child_device_list": children,
                "start_index": start_index,
                "sum": len(children),
            }

        # 4. Control child request
        if method == "control_child":
            device_id = getattr(params, "device_id", None)
            if not device_id and isinstance(params, dict):
                device_id = params.get("device_id")

            req_data = getattr(params, "requestData", None)
            if req_data is None and isinstance(params, dict):
                req_data = params.get("requestData")

            child_req = self._extract_child_request(req_data)
            inner_method = (
                getattr(child_req, "method", None)
                if hasattr(child_req, "method")
                else (child_req.get("method") if isinstance(child_req, dict) else None)
            )

            _LOGGER.debug(
                "H200 control_child for device %s, inner_method: %s",
                device_id,
                inner_method,
            )

            # 4a. Child component negotiation
            if inner_method in ("component_nego", "componentNego"):
                return {
                    "responseData": {
                        "result": {
                            "responses": [
                                {
                                    "component_list": [
                                        {"id": "trigger_log", "ver_code": 1},
                                        {"id": "battery_detect", "ver_code": 1},
                                        {"id": "report_mode", "ver_code": 1},
                                        {"id": "temp_humidity_records", "ver_code": 1},
                                        {"id": "on_off", "ver_code": 1},
                                    ]
                                }
                            ]
                        }
                    }
                }

            # 4b. Child device info
            if inner_method in ("get_device_info", "getDeviceInfo"):
                if not self._children_cache or device_id not in self._children_cache:
                    await self._refresh_children_cache()

                cached_child = self._children_cache.get(device_id, {})
                child_device_info = {
                    "device_id": device_id,
                    "hw_id": cached_child.get("hw_id", "1.0"),
                    "oem_id": cached_child.get("oem_id", "1.0"),
                    "fw_ver": cached_child.get("fw_ver", "1.0.0"),
                    "hw_ver": cached_child.get("hw_ver", "1.0"),
                    "mac": cached_child.get("mac", ""),
                    "nickname": cached_child.get("nickname")
                    or self._ensure_b64(cached_child.get("model", "Child")),
                    "model": cached_child.get("model", "S200B"),
                    "type": cached_child.get("type", "SMART.TAPOBUTTON"),
                    "overheated": cached_child.get("overheated", False),
                    "status": cached_child.get("status", "online"),
                    "at_low_battery": cached_child.get("at_low_battery", False),
                    "battery_percentage": cached_child.get("battery_percentage", -1),
                    "report_interval": cached_child.get("report_interval", 16),
                    "rssi": cached_child.get("rssi", 0),
                    "signal_level": cached_child.get("signal_level", 0),
                    "parent_device_id": cached_child.get("parent_device_id", ""),
                }
                return {"responseData": {"result": {"responses": [child_device_info]}}}

            # 4c. Forward commands to H200 (unwrapping child_req so H200 doesn't receive nested multipleRequest)
            child_payload = self._serialize_tapo_request(child_req)
            child_output = None

            try:
                child_res = await self._execute_command(
                    "controlChild",
                    {
                        "childControl": {
                            "device_id": device_id,
                            "request_data": child_payload,
                        }
                    },
                )
                unwrapped = self._unwrap_child_response(child_res)
                if unwrapped and (
                    "logs" in unwrapped
                    or (isinstance(unwrapped, dict) and len(unwrapped) > 0 and "error_code" not in unwrapped)
                ):
                    child_output = unwrapped
            except Exception as e:
                _LOGGER.debug(
                    "H200 controlChild %s for %s failed: %s",
                    inner_method,
                    device_id,
                    e,
                )

            if child_output is not None:
                if "logs" in child_output and len(child_output["logs"]) > 0:
                    _LOGGER.info(
                        "H200 child %s received %d trigger events: %s",
                        device_id,
                        len(child_output["logs"]),
                        child_output["logs"],
                    )
                return {"responseData": {"result": {"responses": [child_output]}}}

            # Fallback for get_trigger_logs if empty or failed (H200 local firmware does not store trigger logs)
            if inner_method in ("get_trigger_logs", "getTriggerLogs"):
                return {
                    "responseData": {
                        "result": {
                            "responses": [
                                {"start_id": 0, "sum": 0, "logs": []}
                            ]
                        }
                    }
                }

            return {"responseData": {"result": {"responses": [{}]}}}

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
            return {"requests": [self._serialize_tapo_request(r) for r in req.requests]}
        if hasattr(req, "__dict__"):
            return {k: self._serialize_tapo_request(v) for k, v in req.__dict__.items()}
        return req

    def _extract_child_request(self, req_data: Any) -> Any:
        """Unwrap multipleRequest wrapper if present to get the actual sub-device command."""
        if hasattr(req_data, "method"):
            if req_data.method == "multipleRequest":
                inner_params = getattr(req_data, "params", None)
                requests_list = (
                    getattr(inner_params, "requests", None) if inner_params else None
                )
                if requests_list and len(requests_list) > 0:
                    return requests_list[0]
            return req_data
        if isinstance(req_data, dict):
            if req_data.get("method") == "multipleRequest":
                reqs = req_data.get("params", {}).get("requests", [])
                if reqs and len(reqs) > 0:
                    return reqs[0]
            return req_data
        return req_data

    def _unwrap_child_response(self, resp: Any) -> dict[str, Any]:
        """Unwrap H200 childControl / response_data / responseData / result wrappers."""
        if not isinstance(resp, dict):
            return {}
        curr = resp
        for _ in range(5):
            if not isinstance(curr, dict):
                break
            if "childControl" in curr and isinstance(curr["childControl"], dict):
                curr = curr["childControl"]
            elif "response_data" in curr and isinstance(curr["response_data"], dict):
                curr = curr["response_data"]
            elif "responseData" in curr and isinstance(curr["responseData"], dict):
                curr = curr["responseData"]
            elif "result" in curr and isinstance(curr["result"], dict):
                curr = curr["result"]
            else:
                break

        if isinstance(curr, dict) and "logs" in curr:
            logs = curr.get("logs") or []
            normalized_logs = [self._normalize_log_item(item) for item in logs]
            start_id = (
                curr.get("start_id")
                if curr.get("start_id") is not None
                else curr.get("startId", curr.get("start_index", 0))
            )
            sum_count = (
                curr.get("sum") if curr.get("sum") is not None else len(normalized_logs)
            )
            return {
                "start_id": int(start_id or 0),
                "sum": int(sum_count or 0),
                "logs": normalized_logs,
            }

        return curr if isinstance(curr, dict) else {}

    @staticmethod
    def _normalize_log_item(item: Any) -> dict[str, Any]:
        """Normalize log item so parse_s200b_event can parse it regardless of key casing."""
        if not isinstance(item, dict):
            return {}
        norm = dict(item)
        # Event type
        ev = norm.get("event") or norm.get("event_type") or norm.get("type") or ""
        if ev in ("single_click", "singleClick", "SingleClick", "click"):
            norm["event"] = "singleClick"
        elif ev in ("double_click", "doubleClick", "DoubleClick"):
            norm["event"] = "doubleClick"
        elif ev in ("rotation", "rotate", "Rotation"):
            norm["event"] = "rotation"
            if "params" not in norm or not isinstance(norm["params"], dict):
                norm["params"] = {
                    "rotate_deg": norm.get("rotate_deg", norm.get("degrees", 0))
                }

        # ID
        if "id" not in norm:
            if "eventId" in norm:
                norm["id"] = norm["eventId"]
            elif "event_id" in norm:
                norm["id"] = norm["event_id"]
            elif "timestamp" in norm:
                norm["id"] = norm["timestamp"]
            else:
                norm["id"] = 0

        # Timestamp
        if "timestamp" not in norm:
            norm["timestamp"] = norm.get("time", int(time.time()))

        return norm

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
