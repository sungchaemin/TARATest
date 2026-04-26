# 🚗 TARA Pipeline: Automotive Security Test Generator

> **Transform TARA attack trees into executable automotive security test scripts with LLM code generation**

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Anthropic API key for LLM features

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

# Run with LLM features (필수)
export ANTHROPIC_API_KEY="your-api-key"
python core_pipeline/pipeline_runner.py [threats.json] [system_model.json] [output_directory]/

# Input 구조 (and/or)
python core_pipeline/pipeline_runner.py threats.json system_model.json output/
python core_pipeline/pipeline_runner.py threats.json testbed_config.json output/
```

### 3. Target Specific Scenarios
```bash
# Generate scripts for specific attack scenarios
python core_pipeline/pipeline_runner.py inputs/threats.json inputs/system_model.json output/ \
  --scenarios [시나리오_이름]

# Multiple scenarios
python core_pipeline/pipeline_runner.py inputs/threats.json inputs/system_model.json output/ \
  --scenarios [시나리오_이름1] [시나리오_이름2]
```

## 📋 프로젝트 소개

**TARA Pipeline**은 자동차 보안 위험 분석(TARA)에서 생성된 공격 트리를 실제 실행 가능한 보안 테스트 스크립트로 자동 변환하는 연구 프로젝트입니다.

### 🔬 연구 목표
TARA 분석 결과를 바탕으로, 실제 테스트베드에서 실행 가능한 공격 테스트 스크립트를 자동 생성하여 자동차 보안 테스팅의 효율성을 극대화합니다.

## 📁 프로젝트 구조

```
📁 TARATest/
├── 📁 inputs/                          # 입력 데이터 (필수)
│   ├── threats.json                    # TARA 공격 시나리오 정의 (필수)
│   ├── system_model.json               # 테스트베드 시스템 모델 (필수)
│   └── testbed_config.json            # 테스트베드 설정 (필수)
│
├── 📁 core_pipeline/                   # 핵심 파이프라인 엔진
│   ├── pipeline_runner.py             # 메인 실행기 (시작점)
│   ├── step1_prepare_inputs.py        # 1단계: 입력 데이터 전처리
│   ├── step2_decompose_attack.py      # 2단계: 공격 시나리오 분해
│   ├── step3a_bind_controls.py        # 3A단계: 엔드포인트 바인딩
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
│   ├── 📁 output_test/                # 테스트 실행 결과 1
│   ├── 📁 output_test2/               # 테스트 실행 결과 2  
│   ├── 📁 output_test3/               # 테스트 실행 결과 3
│   └── 📁 run_YYYYMMDD_HHMMSS/        # 타임스탬프별 실행 결과 (기본)
│       ├── 📁 steps/                  # 개별 테스트 스크립트
│       │   └── [시나리오이름]/        # 예: TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET/
│       │       └── [경로이름]/        # 예: P_TS_07_DOIP_BYPASS_RESET/
│       │           ├── T1.py          # 1단계 실행 스크립트 (DoIP probe)
│       │           ├── T2.py          # 2단계 실행 스크립트 (routing activation)
│       │           ├── T3.py          # 3단계 실행 스크립트 (SecurityAccess bypass)
│       │           └── T4.py          # 4단계 실행 스크립트 (ECU reset)
│       ├── 📁 assembled/              # 통합 실행 스크립트 (연쇄적 실행)
│       │   └── [시나리오이름]__[경로이름].py  # 예: TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET__P_TS_07_DOIP_BYPASS_RESET.py
│       └── 📁 cache/                  # LLM 응답 캐시 (재현성 보장)
│
└── .gitignore                        # Git 제외 파일
```

## 🔄 사용법 가이드: Input → Output

### 1️⃣ 입력 준비

**필수 입력 파일:**
- `threats.json`: TARA 분석에서 도출된 공격 시나리오 (필수)
- `system_model.json` OR `testbed_config.json`: 테스트베드의 네트워크 토폴로지와 엔드포인트

**threats.json 구조:**
- scenarios: 공격 시나리오 정의
- attack_paths: 공격 경로와 단계별 액션
- steps: 각 단계별 실행할 작업

### 2️⃣ 파이프라인 실행

```bash
# API 키 설정 (LLM 기능 사용시 필수)
export ANTHROPIC_API_KEY="your-api-key"

# 파이프라인 실행
python core_pipeline/pipeline_runner.py \
    [threats.json] \
    [system_model.json] \
    [output_directory]/ \
    --scenarios [시나리오_이름]
```

### 3️⃣ 생성되는 결과물

#### 📁 개별 테스트 스크립트 (`output/run_YYYYMMDD_HHMMSS/steps/`)

각 공격 단계별로 실행 가능한 Python 스크립트가 생성됩니다:
- **T1.py, T2.py, T3.py, T4.py**: 순차 실행 스크립트
- **독립 실행 가능**: 각 스크립트는 개별적으로도 테스트 가능
- **표준 인터페이스**: `run_step(context, artifacts)` 함수 제공
- **실제 프로토콜 구현**: DoIP, CAN, D-Bus, SOME/IP 등 실제 라이브러리 사용
- **testbed_config 주입**: 실제 테스트베드 endpoint 정보 자동 주입

#### 📁 통합 실행 스크립트 (`output/run_YYYYMMDD_HHMMSS/assembled/`)

개별 스크립트들이 하나로 통합된 완전한 테스트 하네스:
- **파일명**: [시나리오이름]__[경로이름].py 형태
- **기능**: 전체 공격 시나리오 연쇄적 자동 실행
- **연쇄 실행**: T1 실패 시 → T2, T3, T4 자동 스킵 (`skipped_chain_failure`)
- **Artifacts 전달**: 각 단계 결과물이 다음 단계로 자동 전달
- **결과**: JSON 형태의 구조화된 관찰 데이터 및 실행 상태

#### 📁 실행 증거 자료 (`output/run_YYYYMMDD_HHMMSS/cache/`)

LLM과의 모든 상호작용이 기록되어 재현 가능성을 보장:
- request_timestamp: 요청 시점
- model: 사용된 LLM 모델
- prompt_hash: 프롬프트 해시값  
- response: 생성된 코드와 추론 과정

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
