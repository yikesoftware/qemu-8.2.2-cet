# QEMU Pseudo-Intel-CET Plugin

Pseudo-Intel-CET functionality plugin based on QEMU 8.2.2 plugin system, with minor modifications to QEMU TCG body code to adapt to Glibc code. The project is currently applicable to ELF emulation in user mode on x86_64 architecture.

## compile

```bash
mkdir build
cd build
../configure --enable-plugins --enable-seccomp --enable-tcg-interpreter --target-list=x86_64-linux-user
make -j`nporc`
```

Plugin location: `./build/tests/plugin/libcet.so`

## Usage

Prepare:

```bash
ln -s ./build/qemu-x86_64 /path/to/qemu-x86_64-cet
ln -s ./build/tests/plugin/ /path/to/plugin/libcet.so
```

Example: 

- `/path/to/qemu-x86_64-cet -plugin /path/to/plugin/libcet.so,mode=user,ibt=on,ss=on,cpu_slots=128 ./cet_test`

or Example with plugin logs: 

- `/path/to/qemu-x86_64-cet -plugin /path/to/plugin/libcet.so,mode=user,ibt=on,ss=on,cpu_slots=128 -d plugin ./cet_test`

Parameters:

- `mode`: This parameter can only be `user`, as testing has only been done in the user state.

- `ibt`: Enable CET IBT (indirect branch tracker) function.

- `ss`: Enable CET SHSTK (shadow stack) funtion.

- `cpu_slots`: We use a separate slot to track and manage the implementation of CETs in each vCPU. The maximum number of vCPUs is usually the maximum number of currently running threads, so make sure that the number of slots is greater than or equal to the number of threads running at the same time.

## Implement

### Major

Plugin code: [cet.c](./blob/main/tests/plugin/cet.c)

### Adaptations for GLIBC

> Maybe this isn't necessary? I just want glibc to normalize its behavior.

Add arch_prctl handler in syscall for CET: [syscall.c](./blob/main/linux-user/syscall.c#L6229)

Add cpu features in CPUID for CET: [cpu.c](./blob/main/target/i386/cpu.c#L6171)

## About

Original README: [README.rst](./README.orig.rst)
