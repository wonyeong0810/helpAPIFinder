# 개인 서버 배포

이 구성은 도메인이 연결된 Linux 개인 서버와 Docker Compose를 기준으로 합니다. 외부에는 Caddy의 80/443 포트만 열리고, Keylight 앱 포트 `8765`는 Docker 내부 네트워크에만 존재합니다.

## 1. 사전 준비

- 서버 도메인의 A/AAAA 레코드를 개인 서버로 연결합니다.
- 방화벽에서 80/TCP와 443/TCP만 웹용으로 엽니다.
- Docker Engine과 Docker Compose 플러그인을 설치합니다.
- GitHub Fine-grained PAT는 공개 저장소 읽기 전용, 짧은 만료 기간으로 준비합니다.

도메인 없이 IP로만 접근하거나 공개 인터넷에 노출하고 싶지 않다면, Caddy 공개 포트 대신 Tailscale 같은 사설망을 사용하는 편이 안전합니다.

## 2. 환경 설정

```bash
cp .env.production.example .env.production
```

`.env.production`의 다음 값을 실제 전용 서브도메인으로 모두 맞춥니다.

```dotenv
KEYLIGHT_DOMAIN=keys.example.com
KEYLIGHT_ALLOWED_HOSTS=keys.example.com
KEYLIGHT_PUBLIC_ORIGIN=https://keys.example.com
KEYLIGHT_ADMIN_USERNAME=admin
```

자동 검사 기본값은 6시간 간격, 최근 7일 내 푸시된 후보 중 최대 10개입니다. `FINDER_SCAN_INTERVAL_MINUTES`는 최소 5분이지만, GitHub 요청 제한과 트래픽을 고려해 60분 이상을 권장합니다.

## 3. Secret 파일 생성

토큰과 비밀번호는 `.env.production`이나 Compose 파일에 쓰지 않습니다.

```bash
mkdir -p secrets
chmod 700 secrets
umask 077

read -rsp "GitHub token: " KEYLIGHT_GITHUB_INPUT
printf '%s' "$KEYLIGHT_GITHUB_INPUT" > secrets/github_token
unset KEYLIGHT_GITHUB_INPUT
echo

read -rsp "Dashboard password: " KEYLIGHT_PASSWORD_INPUT
printf '%s' "$KEYLIGHT_PASSWORD_INPUT" > secrets/admin_password
unset KEYLIGHT_PASSWORD_INPUT
echo
```

관리자 비밀번호는 다른 서비스에서 사용하지 않는 긴 임의 문자열을 사용합니다. 두 파일은 `.gitignore`에 포함되어 있습니다.

## 4. 실행

```bash
docker compose up -d --build
docker compose ps
```

브라우저에서 `https://설정한-도메인`으로 접속하고 `.env.production`의 사용자명과 secret 파일의 비밀번호로 로그인합니다. Caddy가 유효한 DNS와 외부 접근을 확인한 뒤 TLS 인증서를 자동 구성합니다.

로그 확인:

```bash
docker compose logs --tail=100 keylight caddy
```

앱 로그에는 GitHub 토큰이나 탐지된 키 원문을 기록하지 않습니다. 그래도 로그 접근 권한은 서버 관리자에게만 허용하세요.

## 5. 운영

- 수동 검사와 예약 검사가 겹치면 새 검사는 실행되지 않습니다.
- 컨테이너 재시작 도중 실행 중이던 검사는 `실패`로 종료 기록됩니다.
- DB와 HMAC 지문 키는 `keylight_data` 볼륨에 유지됩니다.
- GitHub 토큰은 정기적으로 교체하고, 더 이상 운영하지 않을 때 폐기합니다.
- `8765` 포트를 호스트에 별도로 publish하지 마세요.
- 대시보드를 불특정 사용자에게 공개하지 마세요.

업데이트:

```bash
docker compose up -d --build
```

중지:

```bash
docker compose down
```

`docker compose down -v`는 탐지 DB와 인증서 볼륨까지 삭제하므로 사용하지 마세요.

