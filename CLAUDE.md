# CLAUDE.md — g5se 정밀 구조 가이드

> **대상**: Claude Code, GitHub Copilot, Codex 등 AI 코딩 도구  
> **버전**: g5se v0.1.17 기준 (2026-05-20)  
> **갱신 주기**: 릴리즈마다 업데이트 — 각 섹션 끝 `[last-updated: vX.X.X]` 확인

---

## 목차

1. [전체 아키텍처 & 디렉토리 구조](#1-전체-아키텍처--디렉토리-구조)
2. [요청 흐름 & 라우터](#2-요청-흐름--라우터)
3. [설치 구조 (install)](#3-설치-구조-install)
4. [DB 구조 & 마이그레이션](#4-db-구조--마이그레이션)
5. [보안 레이어](#5-보안-레이어)
6. [알려진 버그 패턴 & 주의사항](#6-알려진-버그-패턴--주의사항)
7. [디자인 시스템 & 테마](#7-디자인-시스템--테마)
8. [커뮤니티 (게시판/회원) 구조](#8-커뮤니티-게시판회원-구조)
9. [쇼핑몰 구조 & 결제 플로우](#9-쇼핑몰-구조--결제-플로우)
10. [장바구니 & 주문 구조](#10-장바구니--주문-구조)
11. [위젯 시스템](#11-위젯-시스템)
12. [업데이트 & 확장 가이드](#12-업데이트--확장-가이드)
13. [코딩 규칙 & 금지 패턴](#13-코딩-규칙--금지-패턴)

---

## 1. 전체 아키텍처 & 디렉토리 구조

```
/                                  Apache DocumentRoot (vhost root)
├── .htaccess                       라우팅·보안 게이트웨이 (6단 규칙)
├── index.php                       프런트 컨트롤러 (유일한 PHP 진입점)
├── app/                            gnuboard 본체 (URL 직접 접근 전면 차단)
│   ├── version.php                 G5SE_VERSION 상수 정의
│   ├── config.php                  경로·URL 상수 (g5se 보정 포함)
│   ├── common.php                  gnuboard 공통 초기화
│   ├── router.php                  Router 클래스 (URL → PHP 파일 매핑)
│   ├── routes/                     사용자 정의 라우트 파일 디렉토리 (v0.1.7+)
│   │   └── _sample.php             라우트 파일 예시
│   ├── _debug.php                  디버그 상태 출력 (개발용)
│   │
│   ├── bbs/                        커뮤니티 핵심 PHP
│   │   ├── board.php               게시판 목록/보기 통합 진입점
│   │   ├── write.php               글쓰기/수정
│   │   ├── delete.php              글삭제
│   │   ├── login.php               로그인 폼
│   │   ├── login_check.php         로그인 처리
│   │   ├── logout.php              로그아웃
│   │   ├── register.php            약관 동의
│   │   ├── register_form.php       회원정보 입력
│   │   ├── register_form_update.php 회원정보 저장
│   │   ├── register_result.php     가입완료
│   │   ├── member_confirm.php      정보수정 비밀번호 확인
│   │   ├── password.php            글/정보수정 비밀번호 확인
│   │   ├── password_lost.php       비번찾기
│   │   ├── password_lost2.php      비번찾기 2단계 (수정: alert_close→alert+redirect)
│   │   ├── password_reset.php      비번재설정 폼
│   │   ├── password_reset_update.php 비번재설정 처리
│   │   ├── member_leave.php        회원탈퇴
│   │   ├── search.php              전체검색 (수정: $str_board_list URL)
│   │   ├── new.php                 새글
│   │   ├── memo.php                쪽지 목록
│   │   ├── memo_form.php           쪽지 작성
│   │   ├── memo_view.php           쪽지 보기
│   │   ├── point.php               포인트 내역
│   │   ├── scrap.php               스크랩 목록
│   │   ├── profile.php             자기소개 (수정: mb_id 없으면 본인 fallback)
│   │   ├── qawrite.php             1:1문의 쓰기 (수정: $action_url → 클린 URL)
│   │   ├── formmail.php            메일보내기
│   │   ├── alert.php               알림 (수정: modern fallback)
│   │   ├── confirm.php             확인창 (수정: modern fallback)
│   │   ├── content.php             정적 콘텐츠
│   │   └── write_token.php         CSRF 토큰 (클린 URL 등록)
│   │
│   ├── adm/                        관리자 (super admin)
│   │   ├── admin.php               관리자 대시보드
│   │   ├── board_form.php          게시판 설정 (수정: URL & 역슬래시 버그 패치)
│   │   ├── db_migrate.php          DB 마이그레이션 도구 (g5se 신규)
│   │   └── ...                     기타 관리자 페이지
│   │
│   ├── lib/                        라이브러리
│   │   ├── mailer.lib.php          PHPMailer 래퍼 (수정: SMTPAutoTLS=false, user_config 연동)
│   │   ├── pbkdf2.lib.php          비밀번호 해시
│   │   └── ...
│   │
│   ├── plugin/                     외부 플러그인 (직접 접근 허용)
│   │   ├── kcaptcha/               한국형 캡차
│   │   │   ├── kcaptcha_image.php  캡차 이미지 생성
│   │   │   ├── kcaptcha_session.php 캡차 세션 관리
│   │   │   └── kcaptcha_mp3.php    캡차 음성 (수정: 디스크→메모리 스트리밍)
│   │   ├── editor/                 CKEditor4 (기본), CKEditor5, smarteditor2
│   │   └── ...                     결제 PG, 소셜로그인 등
│   │
│   ├── install/                    설치 마법사
│   │   ├── install.php             1단계: 라이센스
│   │   ├── install_config.php      2단계: DB 설정
│   │   ├── install_db.php          3단계: DB 생성
│   │   ├── install.inc.php         설치 공통 함수 (수정: data/ 절대경로)
│   │   ├── install.css             설치 스타일 (수정: 서브디렉토리 경로 보정)
│   │   ├── gnuboard5.sql           커뮤니티 스키마 (utf8mb4 + InnoDB + nullable date)
│   │   └── gnuboard5shop.sql       쇼핑몰 스키마
│   │
│   ├── extend/                     훅 확장
│   │
│   ├── shop/                       쇼핑몰 PHP 진입점
│   │   ├── cart.php                장바구니
│   │   ├── orderform.php           주문서
│   │   ├── orderform.sub.php       주문 하위 처리
│   │   ├── orderinquiry.php        주문조회
│   │   ├── orderinquiryview.php    주문상세 (수정: 검색+페이지 합계)
│   │   ├── orderinquirycancel.php  주문취소
│   │   ├── orderaddress.php        배송지 관리
│   │   ├── mypage.php              마이페이지 (커뮤니티+쇼핑 통합)
│   │   ├── search.php              상품검색
│   │   ├── coupon.php              쿠폰
│   │   ├── couponzone.php          쿠폰존
│   │   ├── ordercoupon.php         주문 쿠폰 적용
│   │   ├── personalpay.php         개인결제
│   │   ├── itemrecommend.php       상품 추천 (수정: v0.1.13 UI)
│   │   ├── itemstocksms.php        재고 SMS 알림
│   │   ├── cartoption.php          장바구니 옵션 팝업
│   │   ├── itemoption.php          상품 옵션 팝업
│   │   └── ajax.action.php         장바구니 AJAX (수정: v0.1.16 403 경로)
│   │
│   ├── theme/basic/                기본 테마 (모든 스킨 포함)
│   │   ├── modern/
│   │   │   └── _head.inc.php       ★ 디자인 시스템 핵심
│   │   ├── _nav.inc.php            공통 네비 (수정: v0.1.16 장바구니 수량 갱신)
│   │   ├── _footer.inc.php         공통 푸터
│   │   ├── index.php               메인 페이지
│   │   ├── head.sub.php            gnuboard head (수정: viewport meta 무조건 출력)
│   │   ├── group.php               그룹 페이지 (재작성)
│   │   ├── js/
│   │   │   └── theme.shop.list.js  쇼핑몰 목록 JS (수정: v0.1.16)
│   │   ├── skin/
│   │   │   ├── member/basic/       회원 스킨 (login, register, 비번, 탈퇴 등)
│   │   │   ├── board/basic/        게시판 스킨 (list, view, write, comment, gallery)
│   │   │   ├── shop/basic/         쇼핑몰 스킨 (~36개)
│   │   │   ├── faq/basic/          FAQ 스킨
│   │   │   ├── qa/basic/           1:1문의 스킨 (5개)
│   │   │   ├── memo/basic/         쪽지 스킨
│   │   │   ├── search/basic/       검색 스킨
│   │   │   ├── new/basic/          새글 스킨
│   │   │   ├── connect/basic/      접속자 스킨
│   │   │   └── latest/basic/       최신글 위젯
│   │   └── shop/
│   │       ├── shop.head.php       쇼핑몰 chrome 헤더 (modern sticky nav)
│   │       ├── shop.tail.php       쇼핑몰 chrome 푸터
│   │       └── category.php        카테고리 사이드바
│   │
│   ├── img/  js/  css/  mobile/    정적 자산 (→ /app/ 내부 매핑)
│   └── skin/                       gnuboard5 레거시 호환 skin
│
└── data/                           런타임 (www-data 소유, git 제외)
    ├── dbconfig.php                DB 접속 정보
    ├── user_config.php             사이트별 설정 (v0.1.2+, 시간대·SMTP·캐시)
    ├── session/                    PHP 세션
    ├── cache/                      캐시
    ├── file/                       첨부파일
    ├── member/                     회원 아바타
    └── ...
```

---

## 2. 요청 흐름 & 라우터

### 2.1 요청 처리 흐름

```
브라우저 요청
  │
  ▼
.htaccess (6단 규칙)
  ├─ 1) theme|skin|extend|lib|js|css|img|mobile/*.php → 403
  ├─ 2) /app/* 직접 접근 → 403
  ├─ 3) /data/*.php|html|... → 403
  ├─ 4) theme|skin|img|js|css|mobile|plugin → /app/$1 [END]
  ├─ 5) 실제 파일·디렉토리 → 그대로
  └─ 6) 나머지 → index.php
         │
         ▼
      index.php
         ├─ 상수 사전 정의 (G5_PATH, G5_URL, G5_DATA_PATH, G5SE_VERSION)
         ├─ ob_start 필터 설치 (.php URL → 클린 URL 치환)
         ├─ user_config.php 로드 (있을 경우)
         └─ Router::resolve($_SERVER['REQUEST_URI'])
               │
               ├─ $cleanRoutes 직접 매칭
               ├─ .php 변형 → GET/HEAD: 301 redirect / POST: 패스스루
               ├─ $extraRoutes 정규식 매칭 + named capture → $_GET 주입
               └─ app/routes/*.php 사용자 정의 라우트 파일 (v0.1.7+)
                     │
                     ▼
               ★ index.php 글로벌 스코프에서 require $route_full
               (메서드 내 require 금지 — $g5, $member 등 전역변수 소실)
                     │
                     ▼
               ob_start 필터 → .php URL → 클린 URL 치환 → 응답
```

### 2.2 라우트 전체 목록

| 클린 URL | PHP 파일 | 비고 |
|----------|----------|------|
| `/` | `index.php` | 메인 |
| `/login` | `bbs/login.php` | |
| `/login_check` | `bbs/login_check.php` | POST only |
| `/logout` | `bbs/logout.php` | |
| `/register` | `bbs/register.php` | 약관 |
| `/register_form` | `bbs/register_form.php` | 회원정보 입력 |
| `/register_form_update` | `bbs/register_form_update.php` | POST |
| `/register_result` | `bbs/register_result.php` | |
| `/member_confirm` | `bbs/member_confirm.php` | 정보수정 비번 확인 |
| `/member_leave` | `bbs/member_leave.php` | 탈퇴 |
| `/password` | `bbs/password.php` | 글/정보수정 비번 확인 |
| `/password_check` | `bbs/password_check.php` | POST |
| `/password_lost` | `bbs/password_lost.php` | 비번찾기 |
| `/password_lost_certify` | `bbs/password_lost_certify.php` | |
| `/password_lost2` | `bbs/password_lost2.php` | |
| `/password_reset` | `bbs/password_reset.php` | |
| `/password_reset_update` | `bbs/password_reset_update.php` | POST |
| `/search` | `bbs/search.php` | 전체검색 |
| `/new` | `bbs/new.php` | 새글 |
| `/memo` | `bbs/memo.php` | |
| `/memo_form` | `bbs/memo_form.php` | |
| `/memo_form_update` | `bbs/memo_form_update.php` | POST |
| `/memo_view` | `bbs/memo_view.php` | |
| `/memo_delete` | `bbs/memo_delete.php` | |
| `/formmail` | `bbs/formmail.php` | |
| `/formmail_send` | `bbs/formmail_send.php` | POST |
| `/profile` | `bbs/profile.php` | |
| `/point` | `bbs/point.php` | |
| `/scrap` | `bbs/scrap.php` | |
| `/scrap_delete` | `bbs/scrap_delete.php` | |
| `/scrap_popin` | `bbs/scrap_popin.php` | |
| `/scrap_popin_update` | `bbs/scrap_popin_update.php` | POST |
| `/faq` | `bbs/faq.php` | |
| `/connect` | `bbs/connect.php` | 접속자 |
| `/write_token.php` | `bbs/write_token.php` | CSRF |
| `/board/{bo_table}` | `bbs/board.php` | 게시판 목록 |
| `/board/{bo_table}/{wr_id}` | `bbs/board.php` | 게시글 보기 |
| `/board/{bo_table}/write` | `bbs/write.php` | 글쓰기 |
| `/board/{bo_table}/write/{wr_id}` | `bbs/write.php` | 글수정 |
| `/board/{bo_table}/delete/{wr_id}` | `bbs/delete.php` | |
| `/board/{bo_table}/comment` | `bbs/write_comment.php` | AJAX |
| `/content/{co_id}` | `bbs/content.php` | 정적 페이지 |
| `/group/{gr_id}` | `bbs/group.php` (→`theme/basic/group.php`) | |
| `/qa` | `bbs/qalist.php` | 1:1문의 목록 |
| `/qa/{qa_id}` | `bbs/qaview.php` | |
| `/qa/write` | `bbs/qawrite.php` | |
| `/qa/{qa_id}/edit` | `bbs/qawrite.php?w=u` | |
| `/qa/write_update` | `bbs/qawrite_update.php` | POST |
| `/qa/delete` | `bbs/qadelete.php` | |
| `/api/editor` | `plugin/editor/...` | 에디터 업로드 (v0.1.15+) |
| `/admin/db_migrate` | `adm/db_migrate.php` | DB 마이그레이션 |
| `/shop/list/{ca_id}` | `shop/itemlist.php` | 상품 목록 |
| `/shop/item/{it_id}` | `shop/item.php` | 상품 상세 |
| `/shop/cart` | `shop/cart.php` | 장바구니 |
| `/shop/order` | `shop/orderform.php` | 주문서 |
| `/shop/mypage` | `shop/mypage.php` | |
| `/shop/event/{ev_id}` | `shop/event.php` | |
| `/mypage` | 통합 마이페이지 | 커뮤니티+쇼핑 통합 |
| `/_debug` | `app/_debug.php` | 개발용 |
| `/ajax.{name}.php` | `bbs/ajax.{name}.php` | AJAX 일괄 |

### 2.3 사용자 정의 라우트 (v0.1.7+)

`app/routes/` 디렉토리에 PHP 파일을 두면 Router가 자동 로드:

```php
// app/routes/myroutes.php
return [
    'clean' => [
        '/mypage/orders' => 'shop/myorders.php',
    ],
    'regex' => [
        '#^/item/(?P<it_id>\d+)/?$#' => 'shop/item.php',
    ],
];
```

---

## 3. 설치 구조 (install)

### 3.1 설치 흐름

```
브라우저 → /install/
  ↓
app/install/install.php       1단계: MIT 라이센스 표시 + 동의
  ↓ (동의 후)
/install/install_config       2단계: DB 설정 입력
  ↓
app/install/install_config.php
  DB 호스트, 포트, 이름, 계정, 테이블 접두어, 관리자 설정
  ↓ (설정 저장 후)
/install/install_db           3단계: DB 생성 및 초기 데이터
  ↓
app/install/install_db.php
  ├─ gnuboard5.sql 실행 (커뮤니티 테이블, utf8mb4+InnoDB+nullable date)
  ├─ gnuboard5shop.sql 실행 (쇼핑몰 테이블)
  ├─ g5_config 초기 레코드 삽입
  │   cf_member_skin = 'theme/basic'
  │   cf_skin = 'theme/basic'
  │   cf_editor = 'ckeditor4'   (v0.1.13부터 기본값)
  │   cf_qa_skin = 'theme/basic'
  │   cf_search_skin = 'theme/basic'
  │   cf_faq_skin = 'theme/basic'
  │   cf_new_skin = 'theme/basic'
  │   cf_connect_skin = 'theme/basic'
  │   G5_USE_MOBILE = false     (반응형 단일 CSS)
  ├─ data/dbconfig.php 생성
  └─ 완료 → / 리다이렉트
```

### 3.2 install.inc.php 핵심 수정

```php
// ✅ 절대경로로 data/ 찾기 (Apache CWD 의존 금지)
define('G5_DATA_PATH', dirname(dirname(__DIR__)) . '/data');

// ✅ sql_connect() — die() 대신 예외 (AJAX 처리 가능)
throw new RuntimeException('DB 연결 실패: ' . mysqli_connect_error());
```

### 3.3 서브디렉토리 설치 주의 (v0.1.8~v0.1.12 패치)

서브디렉토리(`/g5se/install/`)에 설치할 때 발생했던 버그들:

- **install.css 경로 깨짐** → `install.php` 내 CSS `href`를 상대경로 또는 `G5_URL` 기반으로
- **install_config 클린 URL 404** → `.htaccess`에 명시적 매핑 추가:
  ```
  RewriteRule ^install/install_config/?$ app/install/install_config.php [L]
  RewriteRule ^install/install_db/?$     app/install/install_db.php [L]
  ```
- **관리자 테마 URL 오류** → `G5_URL` 강제 설정 (자동탐지 SCRIPT_NAME이 `/app/...` 오인)
- **install_db 중복 클릭** → 버튼 disabled 처리 + JS로 차단

### 3.4 data/ 디렉토리 설정

```bash
# 설치 전 필수
mkdir -p data
chmod 707 data
chown www-data:www-data data   # Apache 사용자 소유권
```

`data/user_config.php` (v0.1.2+ — 사이트 별 커스텀):
```php
<?php
// 시간대
date_default_timezone_set('Asia/Seoul');

// 서버 시간 보정 (초 단위)
define('G5_TIME_OFFSET', 0);

// 모바일 분리 사용 여부 (기본 false — 반응형 CSS로 대체)
define('G5_USE_MOBILE', false);

// SMTP 설정
define('G5_SMTP_HOST', 'smtp.example.com');
define('G5_SMTP_PORT', 587);
define('G5_SMTP_USER', 'user@example.com');
define('G5_SMTP_PASS', 'password');
define('G5_SMTP_SECURE', 'tls');    // '' | 'ssl' | 'tls'
define('G5_SMTP_AUTH', true);
define('G5_SMTP_AUTO_TLS', false);  // 로컬 postfix self-signed 회피
```

---

## 4. DB 구조 & 마이그레이션

### 4.1 핵심 테이블 구조

**커뮤니티 테이블**

| 테이블 | 용도 | 핵심 컬럼 |
|--------|------|-----------|
| `g5_config` | 사이트 전체 설정 | cf_* 수십 개 |
| `g5_member` | 회원 | mb_id, mb_password, mb_email, mb_level, mb_expire_date(NULL) |
| `g5_board` | 게시판 설정 | bo_table, bo_skin, bo_use_search |
| `g5_{bo_table}` | 게시물 | wr_id, wr_subject, wr_content, wr_datetime(NULL) |
| `g5_write_comment` | 댓글 | |
| `g5_memo` | 쪽지 | |
| `g5_point` | 포인트 | |
| `g5_scrap` | 스크랩 | |
| `g5_menu` | 메뉴 | me_link (클린 URL 형식 저장) |
| `g5_faq_master` | FAQ 카테고리 | |
| `g5_faq` | FAQ 항목 | |
| `g5_qa_config` | 1:1문의 설정 | qa_skin = 'theme/basic' |
| `g5_qa` | 1:1문의 | |
| `g5_content` | 정적 콘텐츠 | co_id, co_skin = 'theme/basic' |
| `g5_group` | 게시판 그룹 | |
| `g5_visit` | 방문자 | |
| `g5_login` | 접속자 현황 | |

**쇼핑몰 테이블**

| 테이블 | 용도 | 핵심 컬럼 |
|--------|------|-----------|
| `g5_shop_category` | 상품 분류 | ca_id, ca_name, ca_skin |
| `g5_shop_item` | 상품 | it_id, it_name, it_price, it_stock_qty, it_use |
| `g5_shop_item_option` | 상품 옵션 | |
| `g5_shop_cart` | 장바구니 | ct_id, mb_id, it_id, ct_qty, ct_price |
| `g5_shop_order` | 주문 | od_id, od_status, od_pg, od_pay_method |
| `g5_shop_order_item` | 주문 상품 | |
| `g5_shop_coupon` | 쿠폰 | |
| `g5_shop_coupon_member` | 쿠폰 발급 이력 | |
| `g5_shop_wish` | 위시리스트 | |
| `g5_shop_item_qa` | 상품 문의 | |
| `g5_shop_item_use` | 사용 후기 | |
| `g5_shop_delivery` | 배송 | |

### 4.2 DB 설계 원칙

```sql
-- 신규 테이블 필수 설정
ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci

-- date/datetime 컬럼
`wr_datetime`   datetime    NULL DEFAULT NULL   -- zero-date 금지
`mb_expire_date` date       NULL DEFAULT NULL
```

### 4.3 마이그레이션 도구 (`/admin/db_migrate`)

super admin 전용 웹 도구:

```
1. 문자셋 마이그레이션
   utf8mb3 → utf8mb4_unicode_ci
   테이블 단위 ALTER TABLE ... CONVERT TO CHARACTER SET utf8mb4

2. Zero-date 마이그레이션
   NOT NULL date/datetime + DEFAULT '0000-...' 컬럼 탐지
   → NULL DEFAULT NULL ALTER
   → 기존 '0000-...' 값 → NULL UPDATE

3. sql_mode 안내
   NO_ZERO_DATE, NO_ZERO_IN_DATE 추가 권장
   (MariaDB: SET GLOBAL sql_mode=...)
```

### 4.4 NULL-safe 쿼리 패턴

```php
// ❌ 구식 — zero-date 비교
WHERE mb_expire_date = '0000-00-00'
// ✅ NULL-safe
WHERE (mb_expire_date IS NULL OR mb_expire_date = '0000-00-00')

// ❌ isset()은 NULL을 false로 처리
if (!isset($row['mb_datetime'])) { $db->add_column(...); }
// ✅ 컬럼 존재만 확인
if (!array_key_exists('mb_datetime', $row)) { $db->add_column(...); }

// ❌ 날짜 값 하드코딩
$mb_expire_date = '0000-00-00';
// ✅
$mb_expire_date = null; // SQL: VALUES (NULL, ...)
```

### 4.5 g5_config 핵심 설정값 (현재 기본값)

```sql
cf_member_skin     = 'theme/basic'
cf_skin            = 'theme/basic'
cf_editor          = 'ckeditor4'
cf_mobile_skin     = 'theme/basic'
cf_qa_skin         = 'theme/basic'
cf_search_skin     = 'theme/basic'
cf_faq_skin        = 'theme/basic'
cf_new_skin        = 'theme/basic'
cf_connect_skin    = 'theme/basic'
cf_theme           = 'basic'        -- 멀티테마: basic|forest|aurora|sunset
```

---

## 5. 보안 레이어

### 5.1 .htaccess 6단 보안 게이트웨이

```apache
# 1) 정적 폴더 PHP 실행 차단 (plugin 제외 — 캡차·결제 직접 접근 필요)
RewriteRule ^(theme|skin|extend|lib|js|css|img|mobile)/.+\.(php|phtml|phar)$ - [F,L]

# 2) app/ 직접 접근 전면 차단
RewriteRule ^app(/|$) - [F,L]

# 3) data/ 스크립트 실행 차단
RewriteRule ^data/.+\.(php|phtml|phar|html?|cgi|pl|py|jsp|asp|sh)$ - [F,L]

# 4) 정적 자산 → app/ 내부 매핑 [END] 필수
RewriteRule ^(theme|skin|img|js|css|mobile|plugin)/(.*)$ app/$1/$2 [END]

# 5) 실제 파일/디렉토리 통과
RewriteCond %{REQUEST_FILENAME} -f [OR]
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^ - [L]

# 6) 프런트 컨트롤러
RewriteRule ^ index.php [QSA,L]

# 민감 파일 차단
<FilesMatch "(^\.|composer\.(json|lock)|\.env|\.git|\.md|\.sql|\.log)$">
    Require all denied
</FilesMatch>
```

**[END] 플래그 필수 이유**: 없으면 정적 자산(`/theme/...`) 매핑 후 mod_rewrite가 재실행되어 `^app(/|$)` 차단 룰에 걸림.

### 5.2 스킨 파일 보안 가드

```php
<?php if (!defined('_GNUBOARD_')) exit; ?>
```

모든 스킨·include 파일 첫 줄. `index.php`를 거치지 않은 직접 접근 즉시 종료.

### 5.3 CSRF 보호

```php
// write_token.php로 토큰 발급 (클린 URL 등록 필수)
// v0.1.3에서 복구됨 — 누락 시 글쓰기에서 "올바른 방법" 경고 발생
$write_token = get_write_token();
// 폼에 hidden input으로 포함
<input type="hidden" name="token" value="<?= $write_token ?>">
```

### 5.4 파일 업로드 보안

에디터 업로드 라우팅 (v0.1.15+):
```
/api/editor  →  app/plugin/editor/... (세션 컨텍스트 유지)
```
레거시 직접 경로도 호환성 유지 (fallback).

### 5.5 비밀번호 무한 재전송 취약점 수정 (v0.1.x)

```php
// bbs/password_lost2.php
// ❌ 구식 — history.back()으로 재전송 가능
alert_close('인증코드가 틀렸습니다.');
// ✅ 리다이렉트로 폼 재전송 차단
alert('인증코드가 틀렸습니다.', G5_URL.'/password_lost');
```

### 5.6 XSS·SQL Injection

gnuboard 내장 함수 사용:
```php
// 출력 이스케이프
echo htmlspecialchars($var, ENT_QUOTES, 'UTF-8');
echo clean_html($content);  // HTML 퍼미션 기반 필터링

// SQL — PDO named placeholder
$sql = "SELECT * FROM {$g5['member_table']} WHERE mb_id = :mb_id";
sql_fetch($sql, [':mb_id' => $mb_id]);
```

### 5.7 세션 보안

```php
// data/session/ 디렉토리 (www-data 소유)
// PHP 세션 저장소를 기본 /tmp에서 data/session/으로 변경
// user_config.php에서 설정 가능
ini_set('session.save_path', G5_DATA_PATH.'/session');
```

---

## 6. 알려진 버그 패턴 & 주의사항

릴리즈 이력에서 추출한 반복 버그 패턴. **신규 코드 작성 시 반드시 검토.**

### 6.1 경로 & URL 관련

| 버그 | 원인 | 해결 |
|------|------|------|
| `G5_URL`이 `/app/...`으로 잡힘 | `plugin/`에서 직접 실행 시 SCRIPT_NAME 오인 | `config.php`에서 `G5_URL` 강제 정의 (defined() 가드 포함) |
| `G5_DATA_PATH`가 틀린 위치 | `dirname()` 없이 상대경로 | `dirname(G5_PATH).'/data'` 절대경로 사용 |
| 서브디렉토리 설치 시 클린 URL 404 | `.htaccess` rewrite base 미설정 | `RewriteBase /서브경로/` 또는 명시적 매핑 |
| 에디터 업로드 403 | `/app/plugin/editor/...` 직접 접근 차단 | `/api/editor` 라우트 경유 (v0.1.15) |
| 장바구니 AJAX 403 | `ajax.action.php` 경로 오류 | `_nav.inc.php` URL 수정 (v0.1.16) |

### 6.2 HTML & URL 출력 관련

| 버그 | 원인 | 해결 |
|------|------|------|
| 게시판 설정 저장 후 URL에 `&` 노출 | `&` → `&amp;` 미치환 | `htmlspecialchars()` 또는 redirect 처리 |
| 역슬래시가 이미지 경로에 남음 | Windows 경로 구분자 혼입 | `str_replace('\\', '/', $path)` |
| `.php` URL이 클린 URL로 안 바뀜 | `$clean_endpoints`에 미등록 | 배열에 엔드포인트명 추가 |
| 검색 게시판 필터 URL 오류 | `$_SERVER['SCRIPT_NAME']` = `/index.php` | URL을 `/search?...`로 직접 하드코딩 |

### 6.3 다크모드 관련

| 버그 | 원인 | 해결 |
|------|------|------|
| 특정 영역 흰바탕흰글씨 / 검정바탕검정글씨 | 색상 하드코딩 | `var(--m-*)` 토큰으로 교체 |
| gnuboard CSS specificity 충돌 | `.captcha_box`, `.frm_input` 등 원본 CSS | `!important` 덮어쓰기 |
| 버튼 링크 hover 시 글자색 짙어짐 (관리자) | 리셋 규칙 과범위 | `:not(.m-btn):not(.m-link)` 제외 |
| 캡차 스피커 아이콘 깨짐 | gnuboard sprite CSS 충돌 | inline-SVG data-URI로 교체 |

### 6.4 PHP 관련

| 버그 | 원인 | 해결 |
|------|------|------|
| `mysqli_query()` null 에러 | Router 메서드 안에서 require | index.php 글로벌 스코프에서 require |
| `G5_PATH` 중복 정의 Warning | config.php와 index.php 동시 정의 | `defined()` 가드로 보호 |
| CKEditor4 PHP Warning | 비-DHTML 모드에서 초기값 없음 | 기본값 설정 (v0.1.6) |
| PHPMailer STARTTLS 협상 실패 | 로컬 postfix self-signed 인증서 | `$mail->SMTPAutoTLS = false` |
| 스키마 업그레이드 중복 ADD | `isset()` NULL 처리 오인 | `array_key_exists()` 사용 |

### 6.5 모바일 & 반응형 관련

| 버그 | 원인 | 해결 |
|------|------|------|
| 모바일 가로 스크롤 | 고정폭 요소 | `max-width: 100%`, `overflow-x: hidden` |
| viewport meta 미출력 | `G5_IS_MOBILE` 조건부 출력 | 무조건 출력 (v0.1.x 수정) |
| 모바일 버튼 한 줄 초과 | 긴 텍스트 + 아이콘 | 모바일에서 아이콘 숨김 |

---

## 7. 디자인 시스템 & 테마

### 7.1 _head.inc.php — 디자인 시스템 진입점

`app/theme/basic/modern/_head.inc.php` 하나가 모든 모던 스킨의 공통 head 담당.

**포함 내용**:
1. CDN 의존성 (Pretendard 폰트, UnoCSS reset, UnoCSS runtime)
2. 다크모드 FOUC 방지 early init 스크립트
3. CSS 토큰 (`:root` + `[data-theme="dark"]`)
4. 글로벌 컴포넌트 클래스 (`.m-*`)
5. 페이지네이션 `.pg_*` 스타일 (글로벌 hoist)
6. 다크모드 토글 버튼 자동 주입 JS

**중복 로드 방지**:
```php
if (defined('_MODERN_HEAD_LOADED_')) return;
define('_MODERN_HEAD_LOADED_', true);
```

### 7.2 CSS 토큰 전체

```css
:root {
  /* 배경 */
  --m-bg:            #f8fafc;
  --m-surface:       #ffffff;
  --m-surface-2:     #f1f5f9;

  /* 테두리 */
  --m-border:        #e2e8f0;
  --m-border-hover:  #cbd5e1;

  /* 텍스트 */
  --m-text:          #0f172a;
  --m-text-muted:    #64748b;
  --m-text-soft:     #475569;
  --m-text-faint:    #94a3b8;

  /* 주색상 */
  --m-primary:       #2563eb;
  --m-primary-hover: #1d4ed8;
  --m-primary-soft:  rgba(37,99,235,0.12);

  /* 반경 */
  --m-radius-sm:  6px;
  --m-radius:     8px;
  --m-radius-lg:  12px;

  /* 폰트 크기 */
  --m-text-xs:      11px;   /* 뱃지·pill */
  --m-text-sm:      12px;   /* 힌트·설명 */
  --m-text-base:    13px;   /* 기본 레이블 */
  --m-text-md:      14px;   /* input·버튼 */
  --m-text-lg:      16px;   /* 부제목 */
  --m-text-xl:      18px;   /* 섹션 타이틀 */
  --m-text-2xl:     22px;   /* 페이지 타이틀 */
  --m-text-3xl:     26px;   /* 큰 타이틀 */
  --m-text-display: 36px;   /* hero */

  /* line-height */
  --m-leading-tight:   1.3;
  --m-leading:         1.5;
  --m-leading-relaxed: 1.7;

  color-scheme: light;
}

[data-theme="dark"] {
  --m-bg:            #0a0e1a;
  --m-surface:       #131825;
  --m-surface-2:     #1c2230;
  --m-border:        #2a3344;
  --m-border-hover:  #3d4a5e;
  --m-text:          #f1f5f9;
  --m-text-muted:    #94a3b8;
  --m-text-soft:     #cbd5e1;
  --m-text-faint:    #64748b;
  --m-primary:       #3b82f6;
  --m-primary-hover: #60a5fa;
  --m-primary-soft:  rgba(59,130,246,0.20);
  color-scheme: dark;
}
```

### 7.3 컴포넌트 클래스 전체 목록

```
레이아웃
  .m-shell            fixed 오버레이 (inset:0; z-index:9999) — 필수 최상위
  .m-container        max-width 1100px 가운데
  .m-center           풀스크린 가운데 (로그인·완료 카드)
  .m-card             기본 카드
  .m-card-narrow      좁은 카드 (confirm 등)
  .m-popup            팝업 컨테이너

네비게이션
  .m-nav              상단 nav 바 (Row 1: utility, Row 2: menu)
  .m-nav-inner        flex 컨테이너
  .m-brand            브랜드 로고
  .m-nav-actions      우측 액션 (다크모드 토글 JS 자동 주입)

폼
  .m-input            text·email·password input
  .m-textarea         textarea
  .m-file             file input (::file-selector-button 스타일 포함)
  .m-label            폼 레이블
  .m-check            체크박스
  .m-check-block      클릭영역 확장 체크박스
  .m-pw-wrap          비밀번호 래퍼
  .m-pw-toggle        비밀번호 표시/숨기기

버튼
  .m-btn              베이스
  .m-btn-primary      주 액션 (파란)
  .m-btn-secondary    보조
  .m-btn-ghost        테두리만
  .m-icon-btn         아이콘 전용 (케밥 메뉴 등)

텍스트·구분
  .m-link             인라인 텍스트 링크
  .m-divider          "또는" 구분선

게시판
  .m-board-head       게시판 상단 (제목+액션)
  .m-write-section    글쓰기 섹션
  .m-view-header      게시글 헤더
  .m-view-body        게시글 본문
  .m-view-actions     글보기 액션 (목록·답변·글쓰기·케밥)
  .m-pagination       페이지네이션 래퍼 (pg_* 자동 스타일)

다크모드
  .m-theme-toggle     다크모드 토글 버튼
```

### 7.4 멀티테마 (4종)

| 테마 | 특징 | 디렉토리 |
|------|------|----------|
| `basic` | Cool blue, 청회 | `app/theme/basic/` |
| `forest` | Sage green, 자연 | `app/theme/forest/` |
| `aurora` | Lavender violet, 보라 | `app/theme/aurora/` |
| `sunset` | Peach amber, 노을 | `app/theme/sunset/` |

**테마 전환**: `UPDATE g5_config SET cf_theme='forest'`

**새 테마 추가 절차**:
```bash
cp -r app/theme/basic app/theme/mytheme
# symlink 절대 금지 — 격리 깨짐, git 이슈
# app/theme/mytheme/modern/_head.inc.php 의 :root 토큰만 교체
```

### 7.5 상단 Nav 2-row 구조

```
Row 1 (top utility bar):
  브랜드 | 커뮤니티/쇼핑몰 segment | 🔍검색 | FAQ | Q&A | 새글
  접속자 | 🌙다크모드 | 로그인/프로필 | ☰햄버거(모바일)

Row 2 (메인 nav, surface bg):
  홈 | [g5_menu 1차 동적 렌더링] | hover 드롭다운

880px 이하:
  Row 2 + utility → 햄버거 드로어 (우측 슬라이드인)
  드로어: 로그인상태(닉·포인트·쪽지·스크랩) + 5 유틸 + g5_menu
```

`get_menu_db()` 동적 렌더링 — 외부 도메인은 `_blank`, 같은 호스트는 path/query만.

---

## 8. 커뮤니티 (게시판/회원) 구조

### 8.1 게시판 요청 흐름

```
/board/{bo_table}           목록 (bo_wr_id 없음)
/board/{bo_table}/{wr_id}   보기 (bo_wr_id 있음)
  → bbs/board.php
    → $bo_table로 g5_board 레코드 조회
    → bo_skin 값으로 스킨 경로 결정 (= 'theme/basic')
    → skin/board/basic/list.skin.php 또는 view.skin.php include

/board/{bo_table}/write         글쓰기
/board/{bo_table}/write/{wr_id} 수정
  → bbs/write.php → write.skin.php
  → write_token.php로 CSRF 토큰 발급

/board/{bo_table}/comment   댓글 AJAX → bbs/write_comment.php
```

### 8.2 갤러리 게시판

```php
// bo_skin = 'theme/basic' 통일 (v0.1.6)
// list.skin.php → 이미지 grid 레이아웃 자동 전환
if ($board['bo_gallery'] == 1) {
    // 갤러리 모드: 카드 grid
} else {
    // 일반 모드: 테이블
}
```

### 8.3 회원 플로우

```
가입: /register → /register_form → POST /register_form_update → /register_result
로그인: /login → POST /login_check → redirect
비번찾기: /password_lost → 이메일/본인인증 → /password_reset → POST /password_reset_update
정보수정: /member_confirm → (비번 확인 후) → /register_form?w=u → POST /register_form_update
탈퇴: /member_confirm → POST /member_leave
```

### 8.4 스킨 설정 확인

```sql
SELECT cf_member_skin, cf_skin, cf_board_skin,
       cf_qa_skin, cf_search_skin, cf_faq_skin
FROM g5_config;
-- 모두 'theme/basic' 이어야 함
```

---

## 9. 쇼핑몰 구조 & 결제 플로우

### 9.1 쇼핑몰 chrome (shop.head.php)

```
shop.head.php
├─ modern sticky 헤더
│   ├─ TNB (상단 유틸리티 바)
│   ├─ 브랜드 + 검색바
│   ├─ nav (카테고리 1차 + hover 드롭다운)
│   └─ 장바구니·위시리스트 아이콘 (수량 badge)
├─ 사이드 드로어 (모바일)
│   └─ 장바구니, 위시리스트, 주문내역, 마이페이지 바로가기 (v0.1.16)
└─ 다크모드 통합 (m-theme localStorage)

shop.tail.php
└─ modern footer (회사정보 grid + 최신글/접속자 카드)
```

### 9.2 상품 목록 & 상세

```
/shop/list/{ca_id}   → shop/itemlist.php → skin/shop/basic/list.10.skin.php
/shop/item/{it_id}   → shop/item.php    → skin/shop/basic/item.info.skin.php
                                         → skin/shop/basic/item.form.skin.php
```

**상품 스킨 종류** (list 변형):
- `list.10` — 기본 grid 카드 ✅ 완료
- `list.20` — 사이드텍스트 ✗ 미완
- `list.30` — 컴팩트 ✗ 미완
- `list.40` — 리스트뷰 ✗ 미완
- `list.sort` — 정렬 bar ✗ 미완

**메인 상품 위젯 종류**:
- `main.10` — carousel 카드 ✅ 완료 (owl-carousel JS 유지)
- `main.20/40/50` ✗ 미완

### 9.3 결제 플로우

```
상품 상세 (item.form.skin.php)
  ├─ "장바구니 담기" → POST /shop/cart (AJAX) → cart.php
  │     → 성공 시 nav 장바구니 수량 즉시 갱신 (v0.1.16)
  └─ "바로구매" → POST /shop/cart?direct=1 → orderform.php 리다이렉트

장바구니 (/shop/cart → cart.php)
  ├─ 상품 수량 변경 → AJAX → ajax.action.php
  ├─ 선택사항 수정 → 모달 (cartoption.php, v0.1.14 통합 모달)
  ├─ 쿠폰 적용 → ordercoupon.php
  └─ "주문하기" → POST → orderform.php

주문서 (orderform.php + orderform.sub.php)
  ├─ 배송지 선택/등록 → orderaddress.php (모달)
  ├─ 결제수단 선택
  │   ├─ 무통장 입금 → 계좌정보 표시 → od_status = '입금대기'
  │   ├─ 신용카드·기타 → PG 연동 (inicis/lgpay/nicepay/toss)
  │   └─ 테스트 결제 (개발환경)
  ├─ 전화번호 정규화 처리 (v0.1.3)
  └─ 결제 완료 → od_status = '결제완료' → 주문완료 페이지

주문조회 (/shop/orderinquiry → orderinquiry.php)
  ├─ 검색: 주문번호·주문일자 (v0.1.x 수정)
  ├─ 상세: orderinquiryview.php (페이지 합계 표시)
  └─ 취소: orderinquirycancel.php → od_status = '취소'
```

### 9.4 결제 설정 (PG 탭)

관리자 `/admin/shop/pg_set` — PG사 탭별 설정:
- 이니시스 (inicis)
- LG Uplus (lgpay)
- NicePay
- 토스 (toss)
- 무통장 입금

```sql
-- g5_shop_config
sc_pg       -- 기본 PG사
sc_use_pg   -- PG 사용 여부
```

### 9.5 관리자 상품 목록 (v0.1.16)

- 최근 등록순 유지 옵션 추가
- 상품등록 고정 액션 버튼 추가

---

## 10. 장바구니 & 주문 구조

### 10.1 장바구니 테이블 구조

```sql
g5_shop_cart
  ct_id        int PK AUTO_INCREMENT
  mb_id        varchar(20)         -- 로그인 회원 ID (비회원: '')
  ct_session   varchar(50)         -- 비회원 세션 키
  it_id        varchar(20)         -- 상품 ID
  ct_qty       int                 -- 수량
  ct_price     int                 -- 단가 (할인 적용 후)
  ct_option    text                -- 선택 옵션 (직렬화)
  ct_status    varchar(10)         -- '' | 'order'
  ct_add_time  datetime NULL       -- 담은 시각
```

### 10.2 AJAX 장바구니 처리 (v0.1.16 수정)

```javascript
// theme.shop.list.js
// 최신상품 위젯의 "장바구니 담기" AJAX 경로
fetch('/shop/cart', {   // ✅ 클린 URL 경로 (이전: /app/shop/cart.php → 403)
  method: 'POST',
  body: formData
})
.then(r => r.json())
.then(data => {
  // nav 장바구니 수량 즉시 갱신
  document.querySelectorAll('.m-cart-count').forEach(el => {
    el.textContent = data.cart_count;
  });
});
```

### 10.3 선택사항 수정 모달 (v0.1.14)

```javascript
// 기존 새창 팝업 → 공통 모달 레이어로 통합
// cartoption.php 콘텐츠를 .m-modal 안에 로드
// ESC 닫기, 다크모드 색상 적용
```

### 10.4 주문 상태 값

```
od_status:
  '입금대기'    무통장 주문 후
  '결제완료'    PG 결제 성공
  '준비중'      배송 준비
  '배송중'      배송 시작
  '배송완료'    도착 확인
  '취소'        주문 취소
  '반품'        반품 처리
```

---

## 11. 위젯 시스템

### 11.1 위젯 종류 & 경로

| 위젯 | 스킨 경로 | 상태 |
|------|-----------|------|
| 최신글 | `skin/latest/basic/` | ✅ |
| 새글 | `skin/new/basic/` | ✅ |
| 검색 | `skin/search/basic/` | ✅ |
| 접속자 | `skin/connect/basic/` | ✅ |
| 인기글 | `skin/popular/basic/` | 미완 |
| 쇼핑 메인 carousel | `skin/shop/basic/main.10.skin.php` | ✅ |
| 쇼핑 박스 위젯 | `skin/shop/basic/box*.skin.php` | ✗ 미완 |
| 사이드뷰 팝업 | `.sv_wrap .sv` | ✅ |

### 11.2 최신글 위젯 (latest)

```php
// 그룹 페이지 또는 메인에서 include
include G5_SKIN_PATH.'/latest/basic/latest.skin.php';
// $latest_list 배열로 게시물 전달
// 카드형 리스트 렌더링
```

### 11.3 사이드뷰 팝업 (sideview)

```css
/* `:has()` 선택자로 z-index 처리 */
.sv_wrap:has(.sv_on) {
  z-index: 1000;   /* 활성화 시 m-shell 위로 */
}
.m-card { overflow: visible; }  /* 클립 방지 */
```

### 11.4 쇼핑몰 박스 위젯

```php
// 카테고리별 위젯 종류
skin/shop/basic/boxcart.skin.php         장바구니 위젯
skin/shop/basic/boxwish.skin.php         위시리스트
skin/shop/basic/boxcategory.skin.php     카테고리 트리
skin/shop/basic/boxbanner.skin.php       배너
skin/shop/basic/boxevent.skin.php        이벤트
skin/shop/basic/boxtoday.skin.php        오늘 본 상품
skin/shop/basic/boxcommunity.skin.php    커뮤니티 최신글
```

---

## 12. 업데이트 & 확장 가이드

### 12.1 버전 관리

```php
// app/version.php
define('G5SE_VERSION', '0.1.17');
```

업데이트 체크 (관리자 대시보드에서 현재 버전 표시).

### 12.2 gnuboard core 수정 최소화 원칙

수정이 불가피한 경우 파일 상단에 주석 표시:
```php
// [g5se] 수정: G5_URL 강제 설정 — 직접 접근 시 자동탐지 오류 방지
```

**수정된 core 파일 목록**:
```
app/config.php               G5_URL 강제 설정, G5_DATA_PATH 보정
app/common.php               G5_HTTP_BBS_URL 중복 정의 가드
app/lib/mailer.lib.php       SMTPAutoTLS=false, user_config 연동
app/bbs/password_lost2.php   alert → redirect (무한 재전송 차단)
app/bbs/search.php           $str_board_list URL → /search
app/bbs/profile.php          mb_id 없으면 본인 fallback
app/bbs/qawrite.php          $action_url → 클린 URL
app/bbs/alert.php            modern noscript fallback
app/bbs/confirm.php          동일
app/theme/basic/head.sub.php viewport meta 무조건 출력
app/theme/basic/group.php    전면 재작성
app/install/install.inc.php  절대경로, 예외 처리
app/plugin/kcaptcha/kcaptcha_mp3.php 메모리 스트리밍
```

### 12.3 새 페이지 추가 체크리스트

```
□ 1. app/router.php $cleanRoutes에 경로 추가
□ 2. index.php $clean_endpoints 배열에 엔드포인트명 추가
□ 3. 스킨 파일 작성 (_GNUBOARD_ 가드 + _head.inc.php + .m-shell)
□ 4. gnuboard 폼 구조 보존 (action, hidden input, JS 검증함수)
□ 5. 색상·폰트 하드코딩 없는지 검토 (var(--m-*) 사용)
□ 6. 다크모드 토글 후 시각 이상 없는지 확인
□ 7. 모바일(360px) 가로 스크롤 없는지 확인
□ 8. php -l 문법 검사
□ 9. CSRF 토큰 필요 여부 확인 (글쓰기·수정 폼)
□ 10. git diff --check 공백 검사
```

### 12.4 gnuboard5 upstream 병합 시 주의

```
충돌 예상 파일:
  app/config.php          → g5se 보정 부분 유지
  app/common.php          → 중복 정의 가드 유지
  app/bbs/password_lost2.php → redirect 로직 유지
  app/bbs/search.php      → URL 수정 유지
  app/lib/mailer.lib.php  → SMTPAutoTLS 유지
  app/theme/basic/head.sub.php → viewport meta 유지

병합 절차:
  1. git remote add upstream https://github.com/gnuboard/gnuboard5
  2. git fetch upstream
  3. git merge upstream/master --no-ff
  4. 위 파일들 충돌 수동 해결 (g5se 수정 유지)
  5. php -l 전체 검사
  6. 기능 검증 후 버전 bump
```

---

## 13. 코딩 규칙 & 금지 패턴

### ✅ 필수 패턴

```php
// 스킨 보안 가드 (첫 줄 필수)
if (!defined('_GNUBOARD_')) exit;

// 스킨 시작 (디자인 시스템 로드)
require_once(G5_THEME_PATH.'/modern/_head.inc.php');

// CSS 색상 — 토큰만
color: var(--m-text);
background: var(--m-surface);
border: 1px solid var(--m-border);
font-size: var(--m-text-md);

// DB — PDO named placeholder
sql_fetch("SELECT * FROM {$g5['member_table']} WHERE mb_id = :id", [':id' => $id]);

// 날짜 — NULL 사용
$date = null; // not '0000-00-00'

// 컬럼 존재 확인
if (!array_key_exists('col', $row)) { ... }
```

### ❌ 절대 금지

```php
// 1. Router 메서드 안에서 require
class Router {
    public function resolve($uri) {
        require G5_PATH.'/bbs/login.php'; // ❌ 전역변수 소실
    }
}
// → index.php 글로벌 스코프에서만 require

// 2. 색상 하드코딩
color: #333;         // ❌
font-size: 14px;     // ❌

// 3. zero-date
$date = '0000-00-00'; // ❌

// 4. isset()으로 NULL 컬럼 체크
if (!isset($row['col'])) { ... } // ❌

// 5. 테마 symlink
ln -s app/theme/basic app/theme/forest  // ❌

// 6. 스킨 파일 첫 줄 가드 생략 // ❌

// 7. app/ 직접 URL 링크
<a href="/app/bbs/login.php">  // ❌ → /login

// 8. G5SE_VERSION 없이 버전 비교
// → 항상 version.php 상수 참조
```

### 13.1 파일 인코딩 & 서식

```
인코딩: UTF-8 (BOM 없음)
줄바꿈: LF (CRLF 금지)
들여쓰기: 탭 4 (PHP), 스페이스 2 (JS/CSS)
PHP 태그: <?php ?> (short tag 금지)
```

### 13.2 릴리즈 검증 체크리스트

```bash
# PHP 문법 검사 (변경 파일 전체)
php -l app/bbs/changed_file.php

# JS 문법 검사
node --check app/theme/basic/js/theme.shop.list.js

# 공백 검사
git diff --check

# 선택: E2E (Playwright)
# 로그인, 글쓰기, 상품 바로구매, 무통장 주문, 배송 상태 표시
```

---

*이 문서는 g5se v0.1.17 기준. 신규 릴리즈마다 변경 사항을 반영할 것.*  
*참조: `MODERNIZATION.md` (전체 작업 기록), 릴리즈 노트 (github.com/gnuboard/g5se/releases)*
