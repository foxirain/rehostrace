/* SPDX-License-Identifier: GPL-2.0-only */
/* libc-free PID 1 for the generic-scheduler public ARM64 fixture. */

typedef unsigned long size_t;

#include "rehostrace_schedule.h"
#include "rehostrace_boundary_binding_generated.h"

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CLOEXEC 02000000

#define __NR_openat 56
#define __NR_read 63
#define __NR_close 57
#define __NR_write 64
#define __NR_reboot 142
#define __NR_mount 40
#define __NR_finit_module 273
#define __NR_clone 220
#define __NR_wait4 260
#define __NR_exit 93

#define LINUX_REBOOT_MAGIC1 0xfee1dead
#define LINUX_REBOOT_MAGIC2 672274793
#define LINUX_REBOOT_CMD_POWER_OFF 0x4321fedc

static inline long syscall1(long nr, long a0)
{
	register long x0 __asm__("x0") = a0;
	register long x8 __asm__("x8") = nr;
	__asm__ volatile("svc 0" : "+r"(x0) : "r"(x8) : "memory");
	return x0;
}

static inline long syscall3(long nr, long a0, long a1, long a2)
{
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x8 __asm__("x8") = nr;
	__asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
	return x0;
}

static inline long syscall4(long nr, long a0, long a1, long a2, long a3)
{
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x3 __asm__("x3") = a3;
	register long x8 __asm__("x8") = nr;
	__asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
	return x0;
}

static inline long syscall5(long nr, long a0, long a1, long a2, long a3, long a4)
{
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x3 __asm__("x3") = a3;
	register long x4 __asm__("x4") = a4;
	register long x8 __asm__("x8") = nr;
	__asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory");
	return x0;
}

static size_t text_len(const char *text)
{
	size_t length = 0;
	while (text[length])
		length++;
	return length;
}

static void print(const char *text)
{
	syscall3(__NR_write, 1, (long)text, (long)text_len(text));
}

static void print_long(long value)
{
	char buffer[32];
	size_t position = sizeof(buffer);
	unsigned long magnitude;
	int negative = value < 0;

	magnitude = negative ? (unsigned long)(-(value + 1)) + 1 : (unsigned long)value;
	do {
		buffer[--position] = (char)('0' + magnitude % 10);
		magnitude /= 10;
	} while (magnitude);
	if (negative)
		buffer[--position] = '-';
	syscall3(__NR_write, 1, (long)&buffer[position], (long)(sizeof(buffer) - position));
}

static void print_result(const char *label, long value)
{
	print(label);
	print_long(value);
	print("\n");
}

static long load_module(const char *path)
{
	long fd = syscall4(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0);
	long rc;

	if (fd < 0)
		return fd;
	rc = syscall3(__NR_finit_module, fd, (long)"", 0);
	syscall1(__NR_close, fd);
	return rc;
}

static long clone_process(void)
{
	return syscall5(__NR_clone, 17, 0, 0, 0, 0);
}

__attribute__((noreturn)) static void child_exit(long status)
{
	syscall1(__NR_exit, status);
	for (;;)
		;
}

static long read_state(long fd, struct rehostrace_schedule_state *state)
{
	return syscall3(__NR_read, fd, (long)state, sizeof(*state));
}

static void run_fixture(void)
{
	const char actor_a = (char)REHOSTRACE_BOUNDARY_ACTOR_A_PAYLOAD;
	const char actor_b = (char)REHOSTRACE_BOUNDARY_ACTOR_B_PAYLOAD;
	struct rehostrace_schedule_state state;
	long target_fd_a;
	long target_fd_b;
	long state_fd;
	long actor_a_pid;
	long actor_b_pid;
	long status;
	long rc;

	target_fd_a = syscall4(__NR_openat, AT_FDCWD,
			       (long)REHOSTRACE_BOUNDARY_ACTOR_A_ENDPOINT,
			       O_WRONLY | O_CLOEXEC, 0);
	target_fd_b = syscall4(__NR_openat, AT_FDCWD,
			       (long)REHOSTRACE_BOUNDARY_ACTOR_B_ENDPOINT,
			       O_WRONLY | O_CLOEXEC, 0);
	state_fd = syscall4(__NR_openat, AT_FDCWD, (long)"/dev/rehostrace_schedule",
			    O_RDONLY | O_CLOEXEC, 0);
	print_result("REHOSTRACE_PLATFORM_TARGET_A_OPEN fd=", target_fd_a);
	print_result("REHOSTRACE_PLATFORM_TARGET_B_OPEN fd=", target_fd_b);
	print_result("REHOSTRACE_PLATFORM_STATE_OPEN fd=", state_fd);
	if (target_fd_a < 0 || target_fd_b < 0 || state_fd < 0)
		return;

	actor_b_pid = clone_process();
	if (actor_b_pid == 0) {
		unsigned int polls;

		for (polls = 0; polls < 5000000; polls++) {
			rc = read_state(state_fd, &state);
			if (rc == sizeof(state) &&
			    ((state.bits & REHOSTRACE_BOUNDARY_ACTOR_B_START_MASK) ==
			     REHOSTRACE_BOUNDARY_ACTOR_B_START_MASK))
				break;
		}
		if (polls == 5000000)
			child_exit(2);
		print("REHOSTRACE_BOUNDARY_ACTION event=" REHOSTRACE_BOUNDARY_ACTOR_B_EVENT_ID
		      " operation=" REHOSTRACE_BOUNDARY_ACTOR_B_OPERATION "\n");
		rc = syscall3(__NR_write, target_fd_b, (long)&actor_b, 1);
		child_exit(rc == 1 ? 0 : 1);
	}
	print_result("REHOSTRACE_PLATFORM_ACTOR_B pid=", actor_b_pid);

	actor_a_pid = clone_process();
	if (actor_a_pid == 0) {
		print("REHOSTRACE_BOUNDARY_ACTION event=" REHOSTRACE_BOUNDARY_ACTOR_A_EVENT_ID
		      " operation=" REHOSTRACE_BOUNDARY_ACTOR_A_OPERATION "\n");
		rc = syscall3(__NR_write, target_fd_a, (long)&actor_a, 1);
		child_exit(rc == 1 ? 0 : 1);
	}
	print_result("REHOSTRACE_PLATFORM_ACTOR_A pid=", actor_a_pid);

	syscall4(__NR_wait4, actor_a_pid, (long)&status, 0, 0);
	print_result("REHOSTRACE_PLATFORM_ACTOR_A_STATUS value=", status);
	syscall4(__NR_wait4, actor_b_pid, (long)&status, 0, 0);
	print_result("REHOSTRACE_PLATFORM_ACTOR_B_STATUS value=", status);
	rc = read_state(state_fd, &state);
	print_result("REHOSTRACE_PLATFORM_STATE_READ rc=", rc);
	print_result("REHOSTRACE_PLATFORM_FINAL_BITS value=", state.bits);
	print_result("REHOSTRACE_PLATFORM_FINAL_FREES value=", state.counters[0]);
	print_result("REHOSTRACE_PLATFORM_FINAL_TIMEOUTS value=", state.timeouts);
	print("REHOSTRACE_PLATFORM_COMPLETE\n");
	syscall1(__NR_close, state_fd);
	syscall1(__NR_close, target_fd_a);
	syscall1(__NR_close, target_fd_b);
}

__attribute__((noreturn, visibility("default"))) void _start(void)
{
	long rc;

	print("REHOSTRACE_PLATFORM_INIT version=1\n");
	print("REHOSTRACE_BOUNDARY_READY binding=" REHOSTRACE_BOUNDARY_BINDING_ID
	      " binding_sha256=" REHOSTRACE_BOUNDARY_BINDING_SHA256
	      " trace=" REHOSTRACE_BOUNDARY_TRACE_ID
	      " trace_sha256=" REHOSTRACE_BOUNDARY_TRACE_SHA256
	      " schedule_sha256=" REHOSTRACE_BOUNDARY_SCHEDULE_SHA256 "\n");
	rc = syscall5(__NR_mount, (long)"devtmpfs", (long)"/dev", (long)"devtmpfs", 0, 0);
	print_result("REHOSTRACE_PLATFORM_DEVTMPFS rc=", rc);
	rc = load_module("/fixture/rehostrace_seeded_driver.ko");
	print_result("REHOSTRACE_PLATFORM_TARGET_LOAD rc=", rc);
	rc = load_module("/instrumentation/rehostrace_lifetime_schedule.ko");
	print_result("REHOSTRACE_PLATFORM_CONTROLLER_LOAD rc=", rc);
	if (rc == 0)
		run_fixture();
	print("REHOSTRACE_PLATFORM_POWEROFF\n");
	syscall4(__NR_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
		 LINUX_REBOOT_CMD_POWER_OFF, 0);
	for (;;)
		;
}
