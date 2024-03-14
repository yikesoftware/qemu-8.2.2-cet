# QEMU-8.2.2-CET: A Pseudo-Intel-CET Plugin of QEMU

Pseudo-Intel-CET functionality plugin based on QEMU 8.2.2 plugin system, with minor modifications to QEMU TCG to adapt to GLibc. The project is currently applicable to ELF emulation in user mode on x86_64 architecture.

## 1. compile

```bash
mkdir build
cd build
../configure --enable-plugins --enable-seccomp --enable-tcg-interpreter --target-list=x86_64-linux-user
make -j`nporc`
```

Plugin location: `./build/tests/plugin/libcet.so`

## 2. Usage

Prepare:

```bash
ln -s ./build/qemu-x86_64 /path/to/qemu-x86_64-cet
ln -s ./build/tests/plugin/libcet.so /path/to/plugin/libcet.so
```

Example: 

- `/path/to/qemu-x86_64-cet -plugin /path/to/plugin/libcet.so,mode=user,ibt=on,ss=on,cpu_slots=128 ./cet_test`

or Example with plugin logs: 

- `/path/to/qemu-x86_64-cet -plugin /path/to/plugin/libcet.so,mode=user,ibt=on,ss=on,cpu_slots=128 -d plugin ./cet_test`

Parameters:

- `mode`: This parameter can only be `user`, as testing has only been done in the user mode.

- `ibt`: Enable CET IBT (indirect branch tracker) function.

- `ss`: Enable CET SHSTK (shadow stack) funtion.

- `cpu_slots`: We use a separate slot to track and manage the implementation of CETs in each vCPU. The maximum number of vCPUs is usually the maximum number of currently running threads, so make sure that the number of slots is greater than or equal to the number of threads running at the same time.

### Output

CET-IBT violation reports:

```
➜ ./qemu-x86_64-cet -plugin ./plugin/libcet.so,mode=user,ibt=on,ss=on,cpu_slots=128 -d plugin ./cet_test 2
[CET] CET plugin running...
[QEMU] QEMU mode: user
[CET] Physical CPU count: 6
[CET] CPU slots for CET: 128
[CET-IBT] Initialize CET-IBT
[CET-IBT] Initialize CET-SS
[QEMU] vCPU 0 init
Hello, World!
cpuid: eax=0x1, ebx=0x21dc47a9, ecx=0x8041028c, edx=0xa4100010
ibt_supported: 0x1, shstk_supported: 0x1
func_ptr: 0x55555555728d
new_func_ptr: 0x555555557291
[QEMU] vCPU 1 init
target_function
[ERROR] !!! IBT violation (vCPU 1) 
        - caller: 0x5555555574b6        /* callq *%rdx */
        - callee: 0x555555557291        /* pushq %rbp */
[1]    547214 segmentation fault (core dumped)  ./qemu-x86_64-cet -plugin  -d plugin ./cet_test 2
```

CET-SHSTK violation reports:

```
➜  ./qemu-x86_64-cet -plugin ./plugin/libcet.so,mode=user,ibt=on,ss=on,cpu_slots=128 -d plugin ./cet_test
[CET] CET plugin running...
[QEMU] QEMU mode: user
[CET] Physical CPU count: 6
[CET] CPU slots for CET: 128
[CET-IBT] Initialize CET-IBT
[CET-IBT] Initialize CET-SS
[QEMU] vCPU 0 init
Hello, World!
cpuid: eax=0x1, ebx=0x21dc47a9, ecx=0x8041028c, edx=0xa4100010
ibt_supported: 0x1, shstk_supported: 0x1
func_ptr: 0x55555555722d
new_func_ptr: 0x555555557231
[CET-SS] SHSTK violation - Mismatched (vCPU 0)
        - target: 0x555555557508
        - actual: 0x55555555722d
        - caller: 0x555555557503        callq 0x555555557426
        SSP =>  | 3 | 0x555555557508 |  /* callq 0x555555557426 + 5 */
                | 2 | 0x2aaaab334d90 |  /* callq *%rax + 2 */
                | 1 | 0x2aaaab334e40 |  /* callq 0x2aaaab334d10 + 5 */
                | 0 | 0x555555557125 |  /* callq *0x2eb3(%rip) + 6 */
[1]    625148 segmentation fault (core dumped)  ./qemu-x86_64-cet -plugin  -d plugin ./cet_test
```

## 3. Implementation

### Major

Plugin code: [cet.c](./tests/plugin/cet.c)

### Adaptations for GLIBC

> Maybe this isn't necessary? I just want glibc to normalize its behavior.

Add `arch_prctl` syscall handler for CET: [syscall.c](./linux-user/syscall.c#L6229)

Add IBT/SHSTK cpu features in `CPUID` for CET: [cpu.c](./target/i386/cpu.c#L6171)

## 4. About

Original README: [README.rst](./README.orig.rst)

E-Mail: jwdong2000@qq.com
