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

### 예제
```php
<?php
   $file = $_GET['file'];
   include('directory/' . $file);
?>
```
include를 사용함으로써 파일속 PHP 코드를 실행해, 결과적으로 PHP 코드 반복을 줄이고 동적인 페이지를 만들 수 있다.   
하지만 적절한 검증이 이루어지지 않았기 때문에 LFI 취약점이 발생하였다.
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
## 실습 (dreamhack php-1)
위 내용을 토대로 드림핵의 php-1 문제를 풀어보았다.
<img src="/assets\images\posts_img\lfi\lfi-1.png" alt="web image" width="50%">  
List를 클릭했을 때 나오는 화면이다.  
  
당연히 flag.php 파일은 열 수 없없고  
<img src="/assets\images\posts_img\lfi\lfi-2.png" alt="web flag image" width="50%">  

hello.json을 클릭하면 ../uploads/hello.json 파일의 내용이 출력된다.  
<img src="/assets\images\posts_img\lfi\lfi-3.png" alt="web hello.json image" width="50%">  

flag.php파일을 열기 위해 코드를 확인해보았다.  
우선 내용을 출력해주는 view.php 코드이다.
```php
<h2>View</h2>
<pre><?php
    $file = $_GET['file']?$_GET['file']:'';
    if(preg_match('/flag|:/i', $file)){
        exit('Permission denied');
    }
    echo file_get_contents($file);
?>
</pre>
```
flag에 대해서 검증이 이루어지기 때문에 직접적으로는 접근 할 수 없었다.  
여기서 index.php 코드를 보면
```php
<div class="container">
  <?php
    include $_GET['page']?$_GET['page'].'.php':'main.php';
  ?>
</div> 
```
page를 받아 include 하는 코드이다.  
여기서 page에 대한 아무런 검증도 없기 때문에 lfi 취약점이 발생한다.  
  
page 파라미터에 flag 파일 경로인 /var/www/uploads/flag 값을 넣었더니
``` bash
can you see $flag?
```
라고 출력되었다. 우리가 찾던 flag는 $flag 변수 안에 들어 있을 것으로 생각이 들었고,   
flag.php 속 php 코드를 읽기 위해    
php wrapper 중 php://filter wrapper를 사용해 flag 파일에 접근하였다.
``` php
?page=php://filter/convert.base64-encode/resource=/var/www/uploads/flag
```
위 코드는 flag 파일을 base64로 인코딩한 값을 출력할 수 있도록 하는 코드이다.  
page 파라미터에 위 코드를 전송하였고, 출력된 값을 base64로 디코딩 하여 flag 값을 구할 수 있었다.


---
## 참고 자료
**[[Local File Inclusion (LFI): Understanding and Preventing LFI Attacks](https://brightsec.com/blog/local-file-inclusion-lfi/)]**  
**[[What is Local File Inclusion (LFI)?](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/)]**  
**[[From Local File Inclusion to Remote Code Execution – Part 1](https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1/)]**