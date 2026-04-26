def run_step(context: dict, artifacts: dict) -> dict:
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