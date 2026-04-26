# TS_07 DoIP Attack Scenario - Sample Output

이 폴더는 **TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET** 시나리오의 실제 생성 결과물 예시입니다.

## 📁 폴더 구조

```
sample_run/
├── steps/                  # 개별 공격 단계 스크립트
│   └── TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET/
│       └── P_TS_07_DOIP_BYPASS_RESET/
│           ├── T1.py       # DoIP Probe - 게이트웨이 응답 확인
│           ├── T2.py       # Routing Activation - 라우팅 컨텍스트 획득
│           ├── T3.py       # SecurityAccess Bypass - 인증 우회
│           └── T4.py       # ECU Reset - 실제 ECU 재시작
└── assembled/              # 통합 실행 스크립트 (연쇄적 실행)
    └── TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET__P_TS_07_DOIP_BYPASS_RESET.py
```

## 🔗 공격 체인

**T1 → T2 → T3 → T4** 순차 실행
- 각 단계가 성공해야 다음 단계 진행
- 실패 시 이후 단계들 자동 스킵 (`skipped_chain_failure`)

## 🚀 실행 방법

```bash
# 통합 스크립트 실행 (연쇄적)
python examples/output/sample_run/assembled/TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET__P_TS_07_DOIP_BYPASS_RESET.py

# 개별 단계 실행
python examples/output/sample_run/steps/TS_07_DIAGNOSTIC_BYPASS_AND_ECU_RESET/P_TS_07_DOIP_BYPASS_RESET/T1.py
```

## 📋 특징

- **실제 DoIP 라이브러리 사용**: `doipclient` 기반
- **testbed_config 자동 주입**: `172.23.96.1:8445` 엔드포인트
- **Control-free**: NIST SP 800-53 보안 컨트롤 제거
- **Raw attack data**: 순수 공격 관찰 데이터만 수집