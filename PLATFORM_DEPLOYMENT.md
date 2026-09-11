# 백엔드 앱 패널 배포

사용 중인 패널이 Dockerfile을 빌드하고, `PORT` 환경변수의 포트를 Caddy로 프록시하는 경우의 설정입니다. 이 방식에서는 저장소의 `compose.yaml`과 `Caddyfile`을 사용하지 않습니다. 플랫폼이 컨테이너 실행과 HTTPS를 담당하고 루트의 `Dockerfile`만 사용합니다.

## 배포 화면 입력값

| 항목 | 값 |
| --- | --- |
| 이름 | `keylight` |
| 프레임워크 | `Docker (Dockerfile)` |
| 도메인 | 예: `keylight.example.com` 또는 Tailscale 전용 |
| 공개 저장소 주소 | 이 프로젝트를 올린 GitHub 저장소 URL |
| 브랜치 | 기본 브랜치 |
| 하위 폴더 | **비워 두기** |
| 컨테이너 내부 포트 | `8080` |

Dockerfile은 컨테이너 내부의 `0.0.0.0:${PORT}`에 Gunicorn을 바인딩합니다. 패널은 호스트 쪽 포트를 `127.0.0.1`에만 공개하고 Caddy가 그 포트로 프록시해야 합니다. 패널이 `PORT=8080`을 자동 주입하지 않으면 아래 환경변수에도 직접 추가합니다.

## 환경변수

공개 도메인을 연결한 경우:

```dotenv
PORT=8080
FINDER_HOST=0.0.0.0
FINDER_DB_PATH=/data/findings.db
FINDER_SCAN_INTERVAL_MINUTES=15
FINDER_RECENT_DAYS=7
FINDER_MAX_REPOSITORIES=10
KEYLIGHT_REQUIRE_AUTH=1
KEYLIGHT_ADMIN_USERNAME=admin
KEYLIGHT_ADMIN_PASSWORD=충분히-긴-임의-비밀번호
GITHUB_TOKEN=공개저장소-읽기전용-토큰
KEYLIGHT_ALLOWED_HOSTS=keylight.example.com
KEYLIGHT_PUBLIC_ORIGIN=https://keylight.example.com
```

Tailscale로만 접속하고 고정 도메인이 없다면 `KEYLIGHT_ALLOWED_HOSTS`와 `KEYLIGHT_PUBLIC_ORIGIN`은 생략할 수 있습니다. 관리자 인증은 그대로 유지하세요.

패널이 secret 전용 입력란을 제공한다면 `GITHUB_TOKEN`과 `KEYLIGHT_ADMIN_PASSWORD`는 일반 환경변수 칸보다 secret 입력란에 저장합니다. 이 값들을 저장소나 Dockerfile에 넣으면 안 됩니다.

## 반드시 확인할 영구 저장소

현재 DB는 SQLite이며 다음 두 파일이 `/data`에 만들어집니다.

- `/data/findings.db`
- `/data/fingerprint.key`

패널에서 `/data`를 영구 볼륨으로 연결해야 재배포·컨테이너 교체 뒤에도 탐지 기록이 유지됩니다. 영구 볼륨 기능이 없으면 이 Docker 배포 자체는 실행되더라도 데이터가 사라질 수 있습니다. 그런 환경에서는 외부 PostgreSQL 지원을 추가해야 합니다.

## 배포 후 확인

1. `https://설정한-도메인/healthz`가 `{"ok": true}`를 반환하는지 확인합니다.
2. 루트 주소에서 브라우저의 관리자 인증 창이 뜨는지 확인합니다.
3. 로그인 후 `LAST SCAN` 영역에서 자동 검사가 시작됐는지 확인합니다.
4. 패널 로그에 GitHub 토큰이나 탐지된 키 원문이 출력되지 않는지 확인합니다.

자동 검사는 앱 시작 직후 실행되고 이후 설정된 간격으로 반복됩니다. 검사한 저장소는
DB에 기록되어 다음 자동 검사부터 건너뜁니다. 키가 없었던 계정의 새 저장소는 검사하고,
키가 발견된 계정은 새 저장소가 생겨도 제외합니다.

앱 포트를 별도로 공인 IP에 노출하지 말고 패널의 Caddy 또는 Tailscale을 통해서만 접근합니다.
