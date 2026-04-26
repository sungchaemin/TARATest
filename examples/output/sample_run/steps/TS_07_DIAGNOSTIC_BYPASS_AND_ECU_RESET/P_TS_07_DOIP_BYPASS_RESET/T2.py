def run_step(context: dict, artifacts: dict) -> dict:
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