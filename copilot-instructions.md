# g5se — AI 코딩 도구 컨텍스트

> `.github/copilot-instructions.md` / OpenAI Codex용  
> g5se v0.1.17 기준 (2026-05-20)

---

## 프로젝트 정의

**g5se (GNUBOARD5 Second Edition)** — PHP 8.0+ 한국형 커뮤니티·쇼핑몰 플랫폼  
스택: PHP 8.0+, MySQL 5.7+/MariaDB 10.2+, Apache mod_rewrite, Vanilla JS, UnoCSS CDN  
라이선스: MIT  
버전: `app/version.php`의 `G5SE_VERSION` 상수

---

## 아키텍처 한 줄 요약

```
모든 요청 → .htaccess → index.php → Router::resolve() → ★글로벌 스코프 require → gnuboard PHP
                                                          (메서드 내 require 금지)
```

`app/` 디렉토리는 .htaccess로 URL 직접 접근 전면 차단.  
`plugin/`만 예외 (캡차·PG 결제 직접 호출 필요).

---

## 핵심 경로 상수

```php
G5_PATH       // app/ 절대경로
G5_URL        // 도메인 루트 (접두어 없음 — /bbs/ 없음)
G5_DATA_PATH  // data/ 절대경로 (app/ 밖)
G5_THEME_PATH // app/theme/basic 절대경로
G5SE_VERSION  // '0.1.17'

// 전역변수 (common.php 이후)
$g5       // 테이블명 등 시스템 설정
$config   // g5_config 레코드
$member   // 로그인 회원
$is_member // bool
```

---

## 스킨 작성 템플릿

```php
<?php
if (!defined('_GNUBOARD_')) exit; // 보안 가드 — 절대 생략 불가

require_once(G5_THEME_PATH.'/modern/_head.inc.php');
?>
<div class="m-shell"><!-- fixed inset-0 z-9999 오버레이 — 필수 -->
    <header class="m-nav">
        <div class="m-nav-inner">
            <a href="<?= G5_URL ?>" class="m-brand">g5se</a>
            <nav class="m-nav-actions">
                <!-- 다크모드 토글 버튼은 JS 자동 주입 — 수동 추가 불필요 -->
                <?php if ($is_member): ?>
                    <a href="<?= G5_URL ?>/logout" class="m-btn m-btn-ghost">로그아웃</a>
                <?php else: ?>
                    <a href="<?= G5_URL ?>/login" class="m-btn m-btn-ghost">로그인</a>
                <?php endif; ?>
            </nav>
        </div>
    </header>
    <main class="m-center">
        <div class="m-card">
            <!-- 콘텐츠 -->
        </div>
    </main>
</div>
```

팝업/모달 패턴:
```html
<div class="m-popup">
    <div class="m-popup-header">제목</div>
    <div class="m-popup-body">내용</div>
</div>
```

---

## CSS 절대 규칙

```css
/* ❌ 하드코딩 — 다크모드 즉시 파손 */
color: #333;
background: white;
font-size: 14px;

/* ✅ 토큰 사용 */
color: var(--m-text);
background: var(--m-surface);
font-size: var(--m-text-md);

/* gnuboard CSS specificity 충돌 시 */
.captcha_box { background: var(--m-surface) !important; }

/* a 태그 리셋 — 버튼 제외 필수 */
.m-shell a:not(.m-btn):not(.m-link) { color: inherit; }
```

**CSS 토큰 빠른 참조**:

```
배경: --m-bg  --m-surface  --m-surface-2
테두리: --m-border  --m-border-hover
텍스트: --m-text  --m-text-muted  --m-text-soft  --m-text-faint
주색상: --m-primary  --m-primary-hover  --m-primary-soft
반경: --m-radius-sm(6)  --m-radius(8)  --m-radius-lg(12)
폰트: --m-text-xs(11) --m-text-sm(12) --m-text-base(13) --m-text-md(14)
      --m-text-lg(16) --m-text-xl(18) --m-text-2xl(22) --m-text-display(36)
```

---

## 라우터 패턴

### cleanRoutes 추가

```php
// app/router.php
'/mypage' => 'bbs/mypage.php',

// index.php ob_start 필터 등록
static $clean_endpoints = [..., 'mypage'];
```

### extraRoutes (정규식, named capture → $_GET 자동 주입)

```php
'#^/board/(?P<bo_table>[^/]+)/(?P<wr_id>\d+)/?$#' => 'bbs/board.php',
'#^/content/(?P<co_id>[^/]+)/?$#'                  => 'bbs/content.php',
'#^/shop/item/(?P<it_id>[^/]+)/?$#'                => 'shop/item.php',
```

### 사용자 정의 라우트 (v0.1.7+)

`app/routes/myroutes.php`:
```php
return [
    'clean' => ['/my/page' => 'bbs/mypage.php'],
    'regex' => ['#^/item/(\d+)/?$#' => 'shop/item.php'],
];
```

---

## DB 패턴

```php
// 조회
$row = sql_fetch("SELECT * FROM {$g5['member_table']} WHERE mb_id = :id",
                 [':id' => $mb_id]);

// NULL-safe date 비교 (zero-date 병존 환경)
$sql = "WHERE (mb_expire_date IS NULL OR mb_expire_date = '0000-00-00')";

// 쓰기 — NULL 사용 (zero-date 금지)
$datetime = null; // not '0000-00-00 00:00:00'

// 컬럼 존재 확인 (NULL 컬럼 오인 방지)
if (!array_key_exists('col', $row)) { /* 컬럼 없음 */ }
// isset() 금지 — NULL을 false로 오인
```

---

## 쇼핑몰 핵심 흐름

```
상품 상세 → 장바구니 담기(AJAX POST /shop/cart)
         → 바로구매(POST /shop/cart?direct=1)
              ↓
장바구니 (/shop/cart)
  수량변경 → AJAX → /shop/cart (ajax.action.php 경유)
  장바구니 AJAX URL: '/shop/cart' 클린 URL 사용 (app/shop/ 직접 경로 금지)
              ↓
주문서 (/shop/order)
  배송지 선택(모달) → 쿠폰 적용 → 결제수단 선택
  무통장: od_status='입금대기'
  PG결제: inicis/lgpay/nicepay/toss → od_status='결제완료'
              ↓
주문조회 (/shop/orderinquiry) → 취소(/shop/orderinquirycancel)
```

**장바구니 AJAX nav 수량 갱신 (v0.1.16)**:
```javascript
// cart 담기 성공 후
document.querySelectorAll('.m-cart-count').forEach(el => {
    el.textContent = data.cart_count;
});
```

---

## 보안 필수 체크

```php
// 1. 스킨 파일 첫 줄
if (!defined('_GNUBOARD_')) exit;

// 2. CSRF (글쓰기·수정 폼)
$write_token = get_write_token();
// <input type="hidden" name="token" value="<?= $write_token ?>">

// 3. 비밀번호 찾기 — history.back() 재전송 차단
// ❌ alert_close('오류');
// ✅ alert('오류', G5_URL.'/password_lost');

// 4. 에디터 업로드 — /api/editor 경유 (v0.1.15+)
// 직접 /app/plugin/editor/ 경로 금지
```

---

## 설치 체크리스트

```bash
# 1. data/ 디렉토리
mkdir -p data && chmod 707 data
chown www-data:www-data data

# 2. DB 생성
CREATE DATABASE g5se CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

# 3. 브라우저 → /install/ 접근 → 마법사

# 서브디렉토리 설치 시 .htaccess 추가
RewriteBase /서브경로/
RewriteRule ^install/install_config/?$ app/install/install_config.php [L]
RewriteRule ^install/install_db/?$     app/install/install_db.php [L]
```

---

## 알려진 버그 & 수정 패턴

| 증상 | 원인 | 수정 |
|------|------|------|
| `mysqli null` 에러 | Router 메서드 안 require | 글로벌 스코프로 이동 |
| 페이지 빈 화면 | `.m-shell` 누락 | `position:fixed;inset:0;z-index:9999` |
| 다크모드 색상 깨짐 | 하드코딩 | `var(--m-*)` 토큰 교체 |
| 장바구니 AJAX 403 | 경로 오류 | `/shop/cart` 클린 URL |
| 에디터 업로드 403 | 직접 접근 | `/api/editor` 라우트 경유 |
| 게시판 설정 URL `&` 노출 | HTML 미이스케이프 | `htmlspecialchars()` |
| 역슬래시 경로 잔존 | Windows 경로 | `str_replace('\\', '/', $path)` |
| 서브디렉토리 클린 URL 404 | .htaccess base 미설정 | `RewriteBase` 추가 |
| `G5_URL` 자동탐지 오류 | plugin/ 직접 실행 시 SCRIPT_NAME 오인 | `config.php`에서 강제 정의 |
| write token 경고 | 클린 URL 미등록 | `$clean_endpoints`에 추가 |

---

## 멀티테마

```bash
# 신규 테마 추가
cp -r app/theme/basic app/theme/newtheme  # symlink 금지
# app/theme/newtheme/modern/_head.inc.php 의 CSS 토큰만 수정

# 테마 전환
UPDATE g5_config SET cf_theme='newtheme';
```

기존 테마: `basic` `forest` `aurora` `sunset`

---

## 금지 목록 (절대 하드코딩/패턴 금지)

```
❌ Router 메서드 안에서 require
❌ CSS 색상 하드코딩 (#333, white, rgba(0,0,0,0.5) 등)
❌ CSS 폰트 사이즈 하드코딩 (14px 등)
❌ zero-date 신규 사용 ('0000-00-00')
❌ isset()으로 NULL 가능 컬럼 존재 확인
❌ 테마 symlink (cp -r만 허용)
❌ /app/* 직접 URL (클린 URL만)
❌ 스킨 파일 _GNUBOARD_ 가드 생략
❌ ob_start 필터 미등록 상태로 신규 클린 URL 추가
❌ 장바구니 AJAX에 /app/shop/ 직접 경로 사용
```

---

## 릴리즈 검증 명령

```bash
php -l app/changed_file.php       # PHP 문법
node --check app/js/changed.js    # JS 문법
git diff --check                  # 공백
```
