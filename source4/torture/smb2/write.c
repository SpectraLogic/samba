/* 
   Unix SMB/CIFS implementation.

   SMB2 read test suite

   Copyright (C) Andrew Tridgell 2008
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

#include "torture/torture.h"
#include "torture/smb2/proto.h"


#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%u - should be %u\n", \
		       __location__, #v, (unsigned)v, (unsigned)correct); \
		ret = false; \
		goto done; \
	}} while (0)


#define FNAME "smb2_writetest_dat"
#define DNAME "smb2_writetest_dir"


#define MAX_HANDLES 	128
#define MAX_WRITE	(1 << 20)	
static uint8_t 		buf[MAX_WRITE];

static bool test_write(
	struct torture_context *torture, 
	struct smb2_tree *tree, 
	char *dir,
	int nfiles, 
	long fsize, 
	long wsize, 
	bool seq)
{
	int i, j;	
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle hdir;
	struct smb2_handle h[MAX_HANDLES];
	char fname[256];
	offset_t off;
	struct timespec  ts;
	double t0, t1;
	double wtotal = ((long)nfiles * fsize) / (1L << 20L);
	int nwrites = fsize / wsize;
	double msec;



	memset(buf, 0xff, ARRAY_SIZE(buf));
	ZERO_ARRAY(h);

	if (wsize > MAX_WRITE) {
		torture_result(torture, TORTURE_FAIL, __location__ 
			": invalid write size %ld\n", wsize);
		return false;
	}

	if (nfiles > MAX_HANDLES) {
		torture_result(torture, TORTURE_FAIL, __location__ 
			": invalid number of files %d\n", nfiles);
		return false;
	}

	status = torture_smb2_testdir(tree, dir, &hdir);
	torture_assert_ntstatus_ok(torture, status, "Error creating directory");

#undef sprintf

	for (j = 0; j < nfiles; j++) {

		sprintf(fname, "%s\\%s_wsz%ld_nf%d_%s.%d.txt", dir, FNAME, wsize, nfiles,
			seq ? "seq" : "nseq", j);

		//generate_random_str(torture, 16));

		// fprintf(stderr, "%s\n", fname);
		smb2_util_unlink(tree, fname);

		status = torture_smb2_testfile(tree, fname, &h[j]);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	clock_gettime(CLOCK_MONOTONIC, &ts);
	t0 = (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
	// fprintf(stderr, "t0: %F\n", t0);
	
	if (seq) {
		for (j = 0; j < nfiles; j++) {
			for (i = 0, off = 0; i < nwrites; i++, off += wsize) {
				status = smb2_util_write(tree, h[j], buf, off, 
					wsize);
				CHECK_STATUS(status, NT_STATUS_OK);
			}
		}
	} else {
		for (i = 0, off = 0; i < nwrites; i++, off += wsize) {
			for (j = 0; j < nfiles; j++) {
				status = smb2_util_write(tree, h[j], buf, off, 
					wsize);
				CHECK_STATUS(status, NT_STATUS_OK);
			}
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &ts);
	t1 = (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
	// fprintf(stderr, "t1: %F\n", t1);
	t1 = t1 - t0;
	msec = (wtotal / t1);


	for (j = 0; j < nfiles; j++)
	{
		smb2_util_close(tree, h[j]);
		sprintf(fname, "%s.%d", FNAME, j);
		smb2_util_unlink(tree, fname);
	}

	torture_comment(torture, 
		"%d, %ld byte files, %ld write size, written %s " 
		">>> %12F Mbytes/sec\n",
		nfiles,
		fsize,
		wsize,
		seq ?  "sequentially" : "round-robin", 
		msec);

done:
	return ret;

}


static bool test_write_perf(struct torture_context *torture, 
	struct smb2_tree *tree)
{
	bool ret = true;
	int i;
	char randomdir[256];


	struct w_params {
		int nfiles;
		long wsize;
		long fsize;
		bool sequential;
	} wperf_permutations[] = {
		/* nfiles, write size, file size, sequential */
		{1,	1024,	 64 * (1 << 20),	true},
		{1,	4096,	 64 * (1 << 20),	true},
		{1,    16384,	 64 * (1 << 20),	true},
		{1,    32768,	 64 * (1 << 20),	true},
		{1,    65536,	 64 * (1 << 20),	true},
		{1,    65536,	 64 * (1 << 20),	true},

		{8,	1024,	 64 * (1 << 20),	true},
		{8,	1024,	 64 * (1 << 20),	false},
		{8,	4096,	 64 * (1 << 20),	true},
		{8,	4096,	 64 * (1 << 20),	false},
		{8,    16384,	 64 * (1 << 20),	true},
		{8,    16384,	 64 * (1 << 20),	false},
		{8,    32768,	 64 * (1 << 20),	true},
		{8,    32768,	 64 * (1 << 20),	false},
		{8,    65536,	 64 * (1 << 20),	true},
		{8,    65536,	 64 * (1 << 20),	false},

		{16,	4096,	 64 * (1 << 20),	true},
		{16,	4096,	 64 * (1 << 20),	false},
		{16,    16384,	 64 * (1 << 20),	true},
		{16,    16384,	 64 * (1 << 20),	false},
		{16,    32768,	 64 * (1 << 20),	true},
		{16,    32768,	 64 * (1 << 20),	false},
		{16,    65536,	 64 * (1 << 20),	true},
		{16,    65536,	 64 * (1 << 20),	false},

		{32,	4096,	 64 * (1 << 20),	true},
		{32,	4096,	 64 * (1 << 20),	false},
		{32,    16384,	 64 * (1 << 20),	true},
		{32,    16384,	 64 * (1 << 20),	false},
		{32,    32768,	 64 * (1 << 20),	true},
		{32,    32768,	 64 * (1 << 20),	false},
		{32,    65536,	 64 * (1 << 20),	true},
		{32,    65536,	 64 * (1 << 20),	false},

		{64,	4096,	 64 * (1 << 20),	true},
		{64,	4096,	 64 * (1 << 20),	false},
		{64,    16384,	 64 * (1 << 20),	true},
		{64,    16384,	 64 * (1 << 20),	false},
		{64,    32768,	 64 * (1 << 20),	true},
		{64,    32768,	 64 * (1 << 20),	false},
		{64,    65536,	 64 * (1 << 20),	true},
		{64,    65536,	 64 * (1 << 20),	false},

		{32,    (1 << 17), 64 * (1 << 20),	true},
		{32,    (1 << 17), 64 * (1 << 20),	false},
		{32,    (1 << 18), 64 * (1 << 20),	true},
		{32,    (1 << 18), 64 * (1 << 20),	false},
		{32,    (1 << 19), 64 * (1 << 20),	true},
		{32,    (1 << 19), 64 * (1 << 20),	false},

		{64,    (1 << 17), 64 * (1 << 20),	true},
		{64,    (1 << 17), 64 * (1 << 20),	false},
		{64,    (1 << 18), 64 * (1 << 20),	true},
		{64,    (1 << 18), 64 * (1 << 20),	false},
		{64,    (1 << 19), 64 * (1 << 20),	true},
		{64,    (1 << 19), 64 * (1 << 20),	false},

		{128,    (1 << 19), 64 * (1 << 20),	true},
		{128,    (1 << 19), 64 * (1 << 20),	false},
#if 0
		{32,    (1 << 20), 64 * (1 << 20),	true},
#endif
	};


	sprintf(randomdir, "%s-%s", DNAME, generate_random_str(torture, 16));

	for (i = 0; i < ARRAY_SIZE(wperf_permutations); i++)
	{

		test_write(torture, tree, randomdir,
			wperf_permutations[i].nfiles,
			wperf_permutations[i].fsize,
			wperf_permutations[i].wsize,
			wperf_permutations[i].sequential);
	}
done:
	return ret;

}

static bool test_write_f8_s64M_w4k_seq(
	struct torture_context *torture,
	struct smb2_tree *tree)
	
{
	return test_write(torture, tree, DNAME, 8, 64 * (1 << 20), 4096, true); 
}
	
static bool test_write_f8_s64M_w16k_seq(
	struct torture_context *torture,
	struct smb2_tree *tree)
	
{
	return test_write(torture, tree, DNAME, 8, 64 * (1 << 20), 16384, true); 
}
	
static bool test_write_f8_s64M_w64k_seq(
	struct torture_context *torture,
	struct smb2_tree *tree)
	
{
	return test_write(torture, tree, DNAME, 8, 64 * (1 << 20), (1 << 16), true); 
}

static bool test_write_f8_s64M_w128k_seq(
	struct torture_context *torture,
	struct smb2_tree *tree)
	
{
	return test_write(torture, tree, DNAME, 8, 64 * (1 << 20), (1 << 17), true); 
}
	
static bool test_write_f8_s64M_w256k_seq(
	struct torture_context *torture,
	struct smb2_tree *tree)
	
{
	return test_write(torture, tree, DNAME, 8, 64 * (1 << 20), (1 << 18), true); 
}

static bool test_write_f8_s64M_w512k_seq(
	struct torture_context *torture,
	struct smb2_tree *tree)
	
{
	return test_write(torture, tree, DNAME, 8, 64 * (1 << 20), (1 << 19), true); 
}


#if 0
static bool test_write_f8_s64M_w1m_seq(
	struct torture_context *torture,
	struct smb2_tree *tree)
	
{
	return test_write(torture, tree, DNAME, 8, 64 * (1 << 20), (1 << 20), 
		true); 
}
#endif
	
	
struct torture_suite *torture_smb2_write_init(void)
{
	struct torture_suite *suite = 
		torture_suite_create(talloc_autofree_context(), "write");

	torture_suite_add_1smb2_test(suite, "write_perf", 
		test_write_perf);

	torture_suite_add_1smb2_test(suite, "write_f8_s64M_w4k_seq",
		test_write_f8_s64M_w4k_seq);

	torture_suite_add_1smb2_test(suite, "write_f8_s64M_w16k_seq",
		test_write_f8_s64M_w16k_seq);

	torture_suite_add_1smb2_test(suite, "write_f8_s64M_w64k_seq",
		test_write_f8_s64M_w64k_seq);

	torture_suite_add_1smb2_test(suite, "write_f8_s64M_w128k_seq",
		test_write_f8_s64M_w128k_seq);

	torture_suite_add_1smb2_test(suite, "write_f8_s64M_w256k_seq",
		test_write_f8_s64M_w256k_seq);

	torture_suite_add_1smb2_test(suite, "write_f8_s64M_w512k_seq",
		test_write_f8_s64M_w512k_seq);

#if 0
	 doesn't work - NT_STATUS_INTERNAL_ERROR - need to debug 
	torture_suite_add_1smb2_test(suite, "write_f8_s64M_w1m_seq",
		test_write_f8_s64M_w1m_seq);
#endif


	suite->description = talloc_strdup(suite, "SMB2-WRITE tests");

	return suite;
}
