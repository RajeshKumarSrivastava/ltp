// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright Red Hat
 * Author: Rajesh Kumar Srivastava <rajsriva@redhat.com>
 */

/*\
 * [Description]
 *
 * Verify that munlockall(2) fails with unprivileged caller
 */

#include <sys/mman.h>
#include <errno.h>
#include <pwd.h>
#include <sys/resource.h>

#include "tst_test.h"

struct passwd* get_user(char *);
void set_user(char *);
static void verify_munlockall_eperm(void)
{
	unsigned long size = 0;
	struct passwd *ltpuser = get_user("root");

	tst_res(TINFO, "Credentials to user: %ld", ltpuser->pw_uid);

	SAFE_FILE_LINES_SCANF("/proc/self/status", "VmLck: %ld", &size);

	if (size != 0UL)
		tst_brk(TBROK, "Locked memory after init should be 0 but is %ld", size);

	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		tst_brk(TBROK | TERRNO, "Could not lock memory using mlockall()");

	SAFE_FILE_LINES_SCANF("/proc/self/status", "VmLck: %ld", &size);

	if (size == 0UL)
		tst_brk(TBROK, "Locked memory after mlockall() should be > 0");

	set_user("nobody");

	TST_EXP_FAIL(munlockall(), EPERM, "munlockall() fails");

	SAFE_FILE_LINES_SCANF("/proc/self/status", "VmLck: %ld", &size);

	if (size != 0UL)
		tst_res(TPASS, "Locked memory after munlockall() should not be 0 but is %ld", size);
	else
		tst_res(TFAIL, "Memory unlocked without privileged user");
}

struct passwd* get_user(char *name)
{
	return SAFE_GETPWNAM(name);
}

void set_user(char *name)
{
	struct passwd *ltpuser;
	struct group *gr;

	ltpuser = SAFE_GETPWNAM(name);
	gr = SAFE_GETGRGID(ltpuser->pw_gid);
	tst_res(TINFO, "Uer id : %d", geteuid());
	SAFE_SETEUID(ltpuser->pw_uid);

	tst_res(TINFO, "Switching credentials to user: %s, group: %s",
		ltpuser->pw_name, gr->gr_name);
}

static struct tst_test test = {
	.test_all = verify_munlockall_eperm,
	/*
	* As per the documentation
	* if the version is less than 4.11 then the test harness will return TCONF
	* But it doesn't in this case even if we set the kernel version < 4.11
	*/
	.min_kver = "2.6.39",
	.needs_root = 1,
};
