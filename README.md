# RansomwareIsolationKit (Intune & MDE Hybrid)
기업 내 대규모 단말(Intune 환경)에서 랜섬웨어 확산을 획기적으로 차단하기 위한 자동화 도구

본 프로젝트는 기업용 엔드포인트 관리 솔루션인 Microsoft Intune과 Microsoft Defender for Endpoint(MDE)를 연동하여, 랜섬웨어 의심 행위 탐지 시 단말기를 즉각 격리하고 대응하는 자동화 프레임워크입니다.

## 핵심 기능:

Proactive Remediation: Intune을 통한 전사 PC 주기적 상태 점검 및 자동 치료 

Heuristic Detection: 확장자 패턴 및 단시간 대량 파일 변경(Burst Count) 탐지 로직 

Dual Isolation: MDE(Cloud) API 격리와 Local Network(Physical) 격리의 하이브리드 대응

2. 컴플라이언스(Compliance) 연결 (ISO 27001 / ISMS)

ISO 27001:2022 A.16(침해사고 관리): 사고 탐지부터 격리까지의 자동화된 기술적 통제 수단 제공

ISMS-P 2.10(사고 대응 및 복구): 침해 사고 시 즉각적인 대응 및 증거 보존(Evidence Collection) 기능 포함

## 파일 구성 및 기능 설명:

### Detect.ps1 /	탐지 (Detect) /	Intune PR용 스크립트. 확장자 및 파일 변경 임계치(Burst Count)를 감시하여 격리 필요 여부 판단

### Remediate.ps1 /	대응 (Remediate) /	탐지 시 실행되는 대응 스크립트. MDE API 격리 시도 후 실패 시 로컬 네트워크 어댑터 차단

### Invoke-RansomwareEmergencyIsolation.ps1 /	실시간 감시 /	WMI/FileWatcher 기반 실시간 이벤트 감시 및 즉각 격리 실행용 마스터 스크립트

### PR-Undo-Remediate.ps1 /	복구 (Undo) /	Intune을 통해 배포된 격리 조치(방화벽/네트워크 어댑터)를 안전하게 원복

### Undo-EmergencyIsolation.ps1 /	복구 (Undo) /	실시간 감시 도중 수행된 격리 조치를 로컬 환경에서 수동으로 원복

### Install-RansomwareIsolationScheduler.ps1 /	배포 (Install) /	시스템 권한(SYSTEM)으로 감시/대응 스크립트를 스케줄러에 등록하는 설치 파일

### settings.json /	설정 (Config) /	탐지 대상 경로, 제외 패턴(Regex), MDE API 인증 정보 및 격리 정책 설정

### Run_운영 실행 방법_2026.txt /	가이드 /	실제 서버 및 PC 환경에서의 실행 단계와 이벤트 로그 ID 정의서

### 배포 및 운영 팁_2026.txt /	가이드 /	Intune 배포 시 권장 주기(15분~1시간) 및 운영상의 주의사항(Best Practice)

## 핵심 아키텍쳐

1. Dual Layer Isolation: 클라우드(MDE API) 격리와 로컬(네트워크 어댑터 비활성화) 격리를 병행하여 오프라인 상태에서도 확산을 차단합니다.

2. Intune Native: 별도의 에이전트 없이 Intune의 Proactive Remediation 기능을 활용하여 전사 단말의 보안 상태를 폴링(Polling) 방식으로 관리합니다.

3. Audit Trail: 모든 탐지 및 격리 이력은 C:\sec_reports 경로와 Windows 이벤트 로그(Application)에 기록되어 사후 분석 및 인증 심사 증적 자료로 활용됩니다.

## 설치 및 실행

1. settings.json에서 기업 환경에 맞는 테넌트 ID 및 API 정보를 수정합니다.

2. Install-RansomwareIsolationScheduler.ps1을 실행하여 로컬 환경에 구성하거나, Intune 관리 센터에 Detect.ps1과 Remediate.ps1을 등록합니다.
