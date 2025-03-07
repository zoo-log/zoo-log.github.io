---
title: "File Inclusion 취약점 - LFI (Local File Inclusion)"
excerpt: "Local File Inclusion 취약점 알아보기."

categories:
  - WEBHACK
tags:
  - [HACK, WEBHACK]

permalink: /WEBHACK/LFI/

toc: true
toc_sticky: true

date: 2025-03-08
last_modified_at: 2025-03-08
---

## LFI?
`LFI (Local File Inclusion)` : 공격자가 웹 애플리케이션을 통해 민감한 정보를 읽거나 서버의 파일을 실행시킬 수 있는 취약점이다. LFI 취약점이 발생한다면  Directory Traversal, RCE, XSS, 등의 공격으로 이어질 수 있다.  

LFI 취약점은 일반적으로 애플리케이션이 파일 경로를 입력으로 사용할 때 발생한다. 이때 입력값에 대한 적절한 검증이 이루어지지 않을 경우 공격이 진행될 수 있다.

### 에제
다음은 검증이 이루어지지 않아 LFI에 취약한 PHP 코드이다.
```php
<?php
   $file = $_GET['file'];
   include('directory/' . $file);
?>
```

###  Directory Traversal
예시로 위 코드에서 공격자는 url에 `?file=../../../../etc/passwd`와 같이 입력하여 서버의 민감한 파일을 읽을 수 있다.  
Apache.access.log, error.log 또는 소스코드 또한 공격이 가능하다.

### RCE
LFI 취약점은 일반적으로 공격자에게 데이터에 대한 읽기 권한을 제공한다. 하지만 RCE 공격을 통해 권한을 은근슬쩍 침해할 수 있다.
여기서 공격자는 LFI 취약점에서 php wrapper를 더해 RCE 공격을 진행할 수 있다.  
`php wrapper` : PHP에서 다양한 프로토콜을 통해 데이터에 접근할 수 있도록 지원하는 기능이다. http://또한 url형식의 wrapper이다.
**[[PHP Wrappers](https://www.php.net/manual/en/wrappers.php)]**

주로 사용하는 wrapper는 다음과 같다.
- `expect://`  
system command를 실행시켜 준다.  
ex) ?page=expect://ls
- `php://filter`  
I/O 스트림에 대해 다루며, 다양한 유형의 입력을 전달하고 지정한 필터로 필터링할 수 있다.  
ex) ?page=php://filter/convert.base64-encode/resource=flag.php
- `zip://`
zip 파일의 압축을 풀고 안에 들어있는 코드를 실행한다.  
ex) ?page=zip://malicious.zip#shell.php

---
## 실습
공부한 내용을 토대로 드림핵의 php-1 문제를 풀어보았다.

---
## 참고 자료
**[[Local File Inclusion (LFI): Understanding and Preventing LFI Attacks](https://brightsec.com/blog/local-file-inclusion-lfi/)]**  
**[[What is Local File Inclusion (LFI)?](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/)]**  
**[[From Local File Inclusion to Remote Code Execution – Part 1](https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1/)]**