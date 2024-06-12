
首先在 process_client 断点，查看 reqpath buffer 的地址和保存的 ra 地址：

```sh
(gdb) b process_client
Breakpoint 1 at 0x555555556aae: file zookd.c, line 107.

(gdb) c
Continuing.
[Attaching after Thread 0x1555555115c0 (LWP 36169) fork to child process 37680]
[New inferior 2 (process 37680)]
[Detaching after fork from parent process 36169]
[Inferior 1 (process 36169) detached]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Switching to Thread 0x1555555115c0 (LWP 37680)]

Thread 2.1 "zookd-exstack" hit Breakpoint 1, process_client (fd=4) at zookd.c:107
warning: Source file is more recent than executable.
107         if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))

(gdb) info frame
Stack level 0, frame at 0x7fffffffecc0:
 rip = 0x555555556aae in process_client (zookd.c:107); saved rip = 0x555555556a37
 called by frame at 0x7fffffffecf0
 source language c.
 Arglist at 0x7fffffffecb0, args: fd=4
 Locals at 0x7fffffffecb0, Previous frame\'s sp is 0x7fffffffecc0
 Saved registers:
  rbp at 0x7fffffffecb0, rip at 0x7fffffffecb8

(gdb) p &reqpath
$3 = (char (*)[4096]) 0x7fffffffdca0
```

然后继续进入 http_request_line，打印整个调用栈，记录子进程正常处理 http 请求时调用栈的情况：

```sh
(gdb) bt
#0  http_request_line (fd=4, reqpath=0x7fffffffdca0 "\300{!", env=0x55555555b040 <env> "", env_len=0x55555555b010 <env_len>)
    at http.c:67
#1  0x0000555555556ad3 in process_client (fd=4) at zookd.c:107
#2  0x0000555555556a37 in run_server (port=0x7fffffffefc5 "8080") at zookd.c:83
#3  0x00005555555567ce in main (argc=2, argv=0x7fffffffee28) at zookd.c:28
```

发动攻击后，跳转到 http_request，执行完 url_decode(reqpath, sp1) 之后的位置：

```sh
(gdb) b http.c:107
Breakpoint 1 at 0x555555556ec5: file http.c, line 107.
(gdb) c
Continuing.
[Attaching after Thread 0x1555555115c0 (LWP 36169) fork to child process 38263]
[New inferior 2 (process 38263)]
[Detaching after fork from parent process 36169]
[Inferior 1 (process 36169) detached]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Switching to Thread 0x1555555115c0 (LWP 38263)]

Thread 2.1 "zookd-exstack" hit Breakpoint 1, http_request_line (fd=4, reqpath=0x7fffffffdca0 "/", 'A' <repeats 199 times>..., env=0x55555555b040 <env> "REQUEST_METHOD=GET", env_len=0x55555555b010 <env_len>) at http.c:107
warning: Source file is more recent than executable.
107         envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
```

此时再次查看调用栈已经发现：process_client 处栈帧记录的函数返回地址已经被覆盖为 41

```sh
(gdb) bt
#0  http_request_line (fd=4, reqpath=0x7fffffffdca0 "/", 'A' <repeats 199 times>..., env=0x55555555b040 <env> "REQUEST_METHOD=GET", 
    env_len=0x55555555b010 <env_len>) at http.c:107
#1  0x0000555555556ad3 in process_client (fd=4) at zookd.c:107
#2  0x0000555555550041 in ?? ()
#3  0x0000000000000000 in ?? ()
```