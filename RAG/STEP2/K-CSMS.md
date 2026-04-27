# K-CSMS Generation Reference (Step 2)

This document is used for Step 2 planning (LLM enrichment).

Rules:
- Use ONLY Overview, Precondition, Procedure, Keywords
- Do NOT include Result or expected verdict
- Do NOT include PASS/FAIL wording

---

## Test Case: CAN-009
### Title
Vehicle Data Tampering Attempt

### Overview
Verify whether sensitive data stored in the ECU can be manipulated using the WriteDataByIdentifier diagnostic service of the test target.

### Precondition
- CAN Bus of the test target (e.g., OBD Port)
- Diagnostic CAN ID of the test target
- Bitrate of the test target's CAN Bus
- Specification of the test target's diagnostic DID (Data ID)

### Procedure
1. Connect to the CAN Bus of the test target.
2. Refer to the specification of the test target's diagnostic DID to identify DIDs containing sensitive information.
3. Obtain a session using the DiagnosticSessionControl diagnostic service.
4. Verify whether specific information can be manipulated using the WriteDataByIdentifier diagnostic service.

### Keywords
CAN, UDS, WriteDataByIdentifier, DID, session control, tampering

---

## Test Case: ETH-015
### Title
Remote System Function Manipulation Verification

### Overview
Verify whether system functions can be manipulated by remotely connecting to a specific port of the test target system.

### Precondition
- IP address of the test target
- Debug port accessible to the internals of the test target system (e.g., JTAG)

### Procedure
1. Identify the IP address of the test target.
2. Perform port scanning on the IP address of the test target using the python-nmap library.
3. From the port scanning results, identify the system functions (e.g., Media Player) of the open ports.
4. Remotely connect to the open ports and access the system functions identified in the port scanning results to verify whether functions can be manipulated without a separate authentication procedure.

### Keywords
Ethernet, port scan, python-nmap, remote access, unauthenticated access, function manipulation

---

## Test Case: ETH-007
### Title
Major Diagnostic Service Authentication Procedure Verification

### Overview
Verify the authentication procedures of major diagnostic services of the test target's Ethernet service.

### Precondition
- VLAN configuration information
- Diagnostic information of the test target (e.g., IP, Port, Diagnostic ID)
- Specification of services and DIDs available on the test target

### Procedure
1. Connect to the Ethernet of the test target.
2. Configure the VLAN settings on the test PC.
3. Switch the session using the DiagnosticSessionControl service.
4. Among the major diagnostic services, verify the authentication procedure of the services that support NRC 0x33 securityAccessDenied in ISO-14229-1, excluding ECUReset (0x11).
   - ReadDataByIdentifier (0x22)
   - ReadMemoryByAddress (0x23)
   - ReadScalingDataByIdentifier (0x24)
   - ReadDataByPeriodicIdentifier (0x2A)
   - DynamicallyDefineDataIdentifier (0x2C)
   - WriteDataByIdentifier (0x2E)
   - WriteMemoryByAddress (0x3D)
   - InputOutputControlByIdentifier (0x2F)
   - RoutineControl (0x31)
   - RequestDownload (0x34)
   - RequestUpload (0x35)
   - RequestFileTransfer (0x38)
5. Verify that the diagnostic services are properly configured to go through the SecurityAccess procedure.

### Keywords
Ethernet, DoIP, UDS, SecurityAccess, NRC 0x33, diagnostic authentication, privileged services

---

## Test Case: ETH-008
### Title
Sensitive Information Leakage Verification

### Overview
Verify whether sensitive information stored in the ECU can be read using the ReadDataByIdentifier diagnostic service of the test target.

### Precondition
- Information for connecting to the test target via Ethernet
  - IP address, destination port, diagnostic ID of the test target
  - IP address, source port that the test equipment must configure
  - VLAN configuration information
- Specification of the test target's diagnostic DID (Data ID)

### Procedure
1. Connect to the Ethernet of the test target.
2. Configure the Ethernet settings of the test equipment to connect to the test target (IP, VLAN settings, etc.).
3. Obtain a session using the DiagnosticSessionControl diagnostic service.
4. Verify whether sensitive information can be read using the ReadDataByIdentifier diagnostic service.

### Keywords
Ethernet, DoIP, UDS, ReadDataByIdentifier, DID, sensitive data, information leakage