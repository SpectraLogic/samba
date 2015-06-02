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

#include <sys/types.h>
#include <unistd.h>

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
static char buf[MAX_WRITE];

static bool do_read(
	struct torture_context *torture, 
	struct smb2_tree *tree, 
	struct smb2_handle *h,
	long max_off,
	long max_rsize,
	long rcnt)
{
	NTSTATUS status;
	bool	ret = false;
	long	i;
	long 	off;
	long 	last_off;
	long	rsize;
	long	zero = 0;
	struct smb2_read rd;

	


	for (i = 0; i < rcnt; i++)
	{
		TALLOC_CTX *tmp_ctx = talloc_new(torture);

		off = (random() + max_off) % max_off;
		if (off == 0)
		{
			zero++;
			if (zero > 1)
			{
				if (last_off > max_rsize)
				{
					off =  last_off - max_rsize;
				}
				else
				{
					off = i * 7777;
				}
			}
		}
		last_off = off;

		if (off + max_rsize > max_off)
		{
			rsize = off + max_rsize - max_off;
		}
		else
		{
			rsize = max_rsize;
		}
		
		ZERO_STRUCT(rd);
		rd.in.file.handle = *h;
		rd.in.length      = rsize;
		rd.in.offset      = off;
		status = smb2_read(tree, tmp_ctx, &rd);
		talloc_free(tmp_ctx);
		CHECK_STATUS(status, NT_STATUS_OK);
	}
	ret = true;
done:
	return ret;
}

static bool do_read_write(
	struct torture_context *torture, 
	struct smb2_tree *tree, 
	char *dir,
	int nfiles, 
	long fsize, 
	long wsize, 
	long rsize,
	long rmod,
	long rcnt,
	bool seq)
{
	long i, j, r, wcnt;
	bool ret = false;
	NTSTATUS status;
	struct smb2_handle hdir;
	struct smb2_handle h[MAX_HANDLES];
	char fname[MAX_HANDLES][256];
	offset_t off, roff;
	int nwrites = fsize / wsize;
	struct timespec  ts;
	double t0, t1;
	double wtotal = ((long)nfiles * fsize) / (1L << 20L);
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

		sprintf(fname[j], "%s\\%s_wsz%ld_nf%d_%s.%ld.txt", dir, FNAME, wsize, nfiles,
			seq ? "seq" : "nseq", j);

		// fprintf(stderr, "%s\n", fname[j]);
		smb2_util_unlink(tree, fname[j]);

		status = torture_smb2_testfile(tree, fname[j], &h[j]);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	clock_gettime(CLOCK_MONOTONIC, &ts);
	t0 = (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;

	if (seq) {
		for (j = 0; j < nfiles; j++) 
		{
			// Write one file a a time
			//
			wcnt = 0;
			for (i = 0, off = 0; i < nwrites; i++, off += wsize) 
			{
				wcnt++;
				status = smb2_util_write(tree, h[j], buf, off, 
					wsize);
				CHECK_STATUS(status, NT_STATUS_OK);

				if ((wcnt % rmod) == 0)
				{
					if ( ! do_read(torture, tree, &h[j], off + wsize, rsize, rcnt))
					{
						goto done;
					}
				}
			}
		}
	} 
	else 
	{	
		wcnt = 0;
		for (i = 0, off = 0; i < nwrites; i++, off += wsize) {
			for (j = 0; j < nfiles; j++) 
			{
				status = smb2_util_write(tree, h[j], buf, off, 
					wsize);
				CHECK_STATUS(status, NT_STATUS_OK);

				if ((wcnt % rmod) == 0)
				{
					if ( ! do_read(torture, tree, &h[j], off + wsize, rsize, rcnt))
					{
						goto done;
					}
				}
			}
		}
	}
	ret = true;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	t1 = (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
	t1 = t1 - t0;
	msec = (wtotal / t1);

	torture_comment(torture, 
		"%d, %ld byte files, %ld write size, written %s " 
		">>> %12F Mbytes/sec\n",
		nfiles,
		fsize,
		wsize,
		seq ?  "sequentially" : "round-robin", 
		msec);

done:
	for (j = 0; j < nfiles; j++)
	{
		smb2_util_close(tree, h[j]);
		smb2_util_unlink(tree, fname[j]);
	}

	return ret;
}


static bool test_read_write(struct torture_context *torture, 
	struct smb2_tree *tree)
{
	bool ret;
	int i, start;
	char randomdir[256];


	struct w_params {
		int nfiles;
		long wsize;
		long fsize;
		long read_size;
		long read_mod;
		long read_cnt;
		bool sequential;
	} _permutations[] = {
		/* nfiles, wsize, file size, read_size, read modulo, read_cnt, sequential */
		{16,	(1 << 17),	 64L * (1 << 20),  4096, 31, 16, true},
		{16,	(1 << 17),	 64L * (1 << 20),  4096, 31, 16, false},

		{16,	(1 << 17),	 128L * (1 << 20),  8192, 127, 32, true},
		{16,	(1 << 17),	 128L * (1 << 20),  8192, 127,  32, false},

		{8,	(1 << 18),	 256L * (1 << 20),  8192, 257, 32, true},
		{8,	(1 << 18),	 256L * (1 << 20),  8192, 257,  32, false},

		{8,	(1 << 18),	 256L * (1 << 20),  8192, 255, 64, true},
		{8,	(1 << 18),	 256L * (1 << 20),  8192, 255,  64, false},

		{2,	(1 << 19),	 64L * (1 << 30),  8192, 1025, 64, true},
		{2,	(1 << 19),	 64L * (1 << 30),  8192, 1025,  64, false},

		{2,	(1 << 19),	 64L * (1 << 30),  32768, 1280, 64, true},
		{2,	(1 << 19),	 64L * (1 << 30),  32768, 1280,  64, false},

		{2,	(1 << 19),	 64L * (1 << 30),  8192, 1281, 128, true},
		{2,	(1 << 19),	 64L * (1 << 30),  8192, 1281,  128, false},

		{2,	(1 << 17),	 64L * (1 << 30),  (1 << 20), 999, 128, true},
		{2,	(1 << 17),	 64L * (1 << 30),  (1 << 20), 999,  128, false},

		{2,	(1 << 18),	 128L * (1 << 30),  (1 << 20), 640,  32, true},
		{2,	(1 << 18),	 128L * (1 << 30),  (1 << 20), 640,  32, false},

		{2,	(1 << 19),	 128L * (1 << 30),  4096,  964,  32, true},
		{2,	(1 << 19),	 128L * (1 << 30),  4096,  964,  32, false},

		{2,	(1 << 19),	 128L * (1 << 30),  4096,  1281,  64, true},
		{2,	(1 << 19),	 128L * (1 << 30),  4096,  1281,  64, false},
	};

	start = random() % ARRAY_SIZE(_permutations);
	sprintf(randomdir, "%s-%s", DNAME, generate_random_str(torture, 16));
	srandom(getpid());

	i = start;
	do
	{
		torture_comment(torture, "dirname %s, indx %d, nfiles %d, fsize %ld, wsize %ld "
			"read_size %ld, read_mod %ld, read_cnt %ld, "
			"sequential %d\n",
			randomdir, i,
			_permutations[i].nfiles,
			_permutations[i].fsize,
			_permutations[i].wsize,
			_permutations[i].read_size,
			_permutations[i].read_mod,
			_permutations[i].read_cnt,
			_permutations[i].sequential);

		ret = do_read_write(torture, tree, randomdir,
			_permutations[i].nfiles,
			_permutations[i].fsize,
			_permutations[i].wsize,
			_permutations[i].read_size,
			_permutations[i].read_mod,
			_permutations[i].read_cnt,
			_permutations[i].sequential);

		i = (i + 1) %  ARRAY_SIZE(_permutations);

	} while (ret && (i != start));
done:
	return ret;

}

struct torture_suite *torture_smb2_read_write_init(void)
{
	struct torture_suite *suite = 
		torture_suite_create(talloc_autofree_context(), "read_write");

	torture_suite_add_1smb2_test(suite, "read_write", test_read_write);

	suite->description = talloc_strdup(suite, "SMB2-READ_WRITE tests");

	return suite;
}
