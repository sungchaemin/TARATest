# 🚗 TARA Pipeline: Automotive Security Test Generator

> **Transform TARA attack trees into executable automotive security test scripts with AI-powered code generation**

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- *(Optional)* Anthropic API key for LLM features

### 1. Installation
```bash
git clone https://github.com/sungchaemin/TARATest.git
cd TARATest
```

### 2. Basic Usage
```bash
# Test the setup
python examples/test_setup.py

# Run without LLM (stub mode) 
python examples/example_run.py

# Run with LLM features
export ANTHROPIC_API_KEY="your-api-key"
python core_pipeline/pipeline_runner.py inputs/threats.json inputs/system_model.json output/
```

### 3. Target Specific Scenarios
```bash
# Generate scripts for specific attack scenarios
python core_pipeline/pipeline_runner.py inputs/threats.json inputs/system_model.json output/ \
  --scenarios TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET

# Multiple scenarios
python core_pipeline/pipeline_runner.py inputs/threats.json inputs/system_model.json output/ \
  --scenarios TS_04_SAFETY_CRITICAL_CAN_INJECTION TS_05_COMFORT_BUS_INJECTION
```

## 📋 프로젝트 소개

**TARA Pipeline**은 자동차 보안 위험 분석(TARA)에서 생성된 공격 트리를 실제 실행 가능한 보안 테스트 스크립트로 자동 변환하는 연구 프로젝트입니다.

### 🔬 연구 목표
ISO/SAE 21434 표준에 따른 TARA 분석 결과를 바탕으로, 실제 테스트베드에서 실행 가능한 침투 테스트 스크립트를 자동 생성하여 자동차 보안 테스팅의 효율성을 극대화합니다.

## 📁 프로젝트 구조

```
📁 TARATest/
├── 📁 inputs/                          # 입력 데이터
│   ├── threats.json                    # TARA 공격 시나리오 정의
│   ├── system_model.json               # 테스트베드 시스템 모델
│   ├── testbed_config.json            # 테스트베드 설정
│   ├── nist_800_53_rev5.json          # NIST 보안 컨트롤 데이터베이스
│   └── jeep_whitepaper_function_level_*.json  # 실제 차량 시나리오
│
├── 📁 core_pipeline/                   # 핵심 파이프라인 엔진
│   ├── pipeline_runner.py             # 메인 실행기 (시작점)
│   ├── step1_prepare_inputs.py        # 1단계: 입력 데이터 전처리
│   ├── step2_decompose_attack.py      # 2단계: 공격 시나리오 분해
│   ├── step3a_bind_controls.py        # 3A단계: 보안 컨트롤 바인딩
│   ├── step3b_generate_scripts.py     # 3B단계: 테스트 스크립트 생성
│   ├── step5_assemble_v3.py           # 5단계: 최종 스크립트 어셈블리
│   ├── llm_enricher.py                # LLM 통신 관리
│   ├── contract_verifier.py           # 코드 안전성 검증
│   ├── safety_validator.py            # 보안 유효성 검사
│   └── pipeline_types.py              # 타입 정의
│
├── 📁 examples/                        # 예제 및 테스트
│   ├── example_run.py                 # 기본 실행 예제
│   └── test_setup.py                  # 설치 확인 스크립트
│
├── 📁 output/                         # 생성된 결과물 (실행시 자동 생성)
│   └── run_YYYYMMDD_HHMMSS/           # 타임스탬프별 실행 결과
│       ├── 📁 steps/                  # 개별 테스트 스크립트
│       │   └── TS_XX_SCENARIO_NAME/
│       │       └── P_TS_XX_PATH/
│       │           ├── T1.py          # 1단계 실행 스크립트
│       │           ├── T2.py          # 2단계 실행 스크립트
│       │           └── ...
│       ├── 📁 assembled/              # 통합 실행 스크립트
│       │   └── TS_XX_*.py            # 완전한 테스트 하네스
│       └── 📁 cache/                  # LLM 응답 캐시
│
└── .gitignore                        # Git 제외 파일
```

## 🔄 사용법 가이드: Input → Output

### 1️⃣ 입력 준비

**필수 입력 파일:**
- `inputs/threats.json`: TARA 분석에서 도출된 공격 시나리오
- `inputs/system_model.json`: 테스트베드의 네트워크 토폴로지와 엔드포인트

**예시 - threats.json:**
```json
{
  "scenarios": {
    "TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET": {
      "description": "진단 시스템 우회를 통한 ECU 리셋",
      "attack_paths": [
        {
          "path_id": "P_TS_07_DOIP_BYPASS_RESET",
          "steps": [
            {"id": "T1", "action": "DoIP 연결 및 라우팅 활성화"},
            {"id": "T2", "action": "차량 식별 요청"},
            {"id": "T3", "action": "진단 세션 설정"},
            {"id": "T4", "action": "ECU 리셋 명령 실행"}
          ]
        }
      ]
    }
  }
}
```

### 2️⃣ 파이프라인 실행

```bash
# API 키 설정 (LLM 기능 사용시)
export ANTHROPIC_API_KEY="sk-ant-api-xxxxx"

# 파이프라인 실행
python core_pipeline/pipeline_runner.py \
    inputs/threats.json \
    inputs/system_model.json \
    output/ \
    --scenarios TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET
```

### 3️⃣ 생성되는 결과물

#### 📁 개별 테스트 스크립트 (`output/run_YYYYMMDD_HHMMSS/steps/`)

각 공격 단계별로 실행 가능한 Python 스크립트가 생성됩니다:

**T1.py 예시 (DoIP 연결):**
```python
import time
import socket
from doipclient import DoIPClient

def run_step(context: dict, artifacts: dict) -> dict:
    # DoIP 클라이언트 설정
    endpoint = {
        "host": "172.23.96.1",
        "port": 8445,
        "protocol": "doip_tcp"
    }
    
    # 연결 시도
    client = DoIPClient(
        ecu_ip_address=endpoint["host"],
        ecu_logical_address=0x00E0,
        tcp_port=endpoint["port"]
    )
    
    # 결과 반환
    return {
        "observations": [{"name": "doip_connection", "value": True}],
        "artifacts": {"client": client},
        "notes": "DoIP 라우팅 활성화 성공"
    }
```

#### 📁 통합 실행 스크립트 (`output/run_YYYYMMDD_HHMMSS/assembled/`)

개별 스크립트들이 하나로 통합된 완전한 테스트 하네스:

**TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET__P_TS_07_DOIP_BYPASS_RESET.py**
- **크기**: ~28KB (약 770라인)
- **기능**: 전체 공격 시나리오 자동 실행
- **결과**: JSON 형태의 구조화된 관찰 데이터

#### 📁 실행 증거 자료 (`output/run_YYYYMMDD_HHMMSS/cache/`)

LLM과의 모든 상호작용이 기록되어 재현 가능성을 보장:

```json
{
  "request_timestamp": "2026-04-26T17:43:52Z",
  "model": "claude-3-5-sonnet-20241022",
  "prompt_hash": "3ebfa7e6267018a8",
  "response": {
    "generated_code": "...",
    "reasoning": "DoIP 프로토콜 특성을 고려하여..."
  }
}
```

### 4️⃣ 결과 활용

#### ✅ 즉시 실행 가능
생성된 assembled 폴더의 통합 스크립트를 바로 실행할 수 있습니다.

#### ✅ 구조화된 결과 데이터
실행 결과는 JSON 형태로 관찰 데이터와 증거 자료가 포함됩니다.

## ⚙️ Configuration

### API Key Setup
```bash
# Temporary (current session)
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Windows
setx ANTHROPIC_API_KEY "sk-ant-your-key-here"
```

### Command Line Options
```bash
python core_pipeline/pipeline_runner.py [threats] [system_model] [output] [options]

Options:
  --scenarios SCENARIO [SCENARIO ...]   Target specific scenarios
  --api-key API_KEY                     Anthropic API key
  --no-llm                              Disable LLM (use stubs)
  --run-name NAME                       Custom output folder name  
  --no-timestamp                        Disable timestamped folders
  --help                                Show help message
```

---

**Made with 🚗 for automotive security research**