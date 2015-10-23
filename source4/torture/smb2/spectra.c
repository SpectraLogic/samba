/* 
   Unix SMB/CIFS implementation.

   test suite for SMB2 connection operations

   Copyright (C) Andrew Tridgell 2005
   
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

#include <unistd.h>
#include <pthread.h>
#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"


extern NTSTATUS torture_smb2_close(struct smb2_tree *tree, struct smb2_handle handle);
extern NTSTATUS torture_smb2_write(struct torture_context *tctx, struct smb2_tree *tree, struct smb2_handle handle);
extern struct smb2_handle torture_smb2_createfile(struct smb2_tree *tree, 
                          const char *fname);

#define CHECK_STATUS(status, correct) do { \
    if (!NT_STATUS_EQUAL(status, correct)) { \
        printf("(%s) Incorrect status %s - should be %s\n", \
               __location__, nt_errstr(status), nt_errstr(correct)); \
        ret = false; \
        goto done; \
    }} while (0)

#define FNAME_MAX 64
#define MAX_WRITE (1 << 20)

typedef struct torture_thread_context
{
    int         tt_pid;
    int         tt_id;
    int         tt_max_related;
    int         tt_max_write;
    char        tt_fname[FNAME_MAX];
    double      tt_msec;
    TALLOC_CTX* tt_memctx;
    struct smb2_tree*   tt_tree;
    struct smb2_handle  tt_handle;
    struct torture_context*  tt_tctx;
} tthrd_ctx;

int
writex(tthrd_ctx *tthrd)
{
    long i, j;
    int ret = 0;
    NTSTATUS status;
    uint32_t size = torture_setting_int(tthrd->tt_tctx, "smb2maxwrite", 64*1024);
    DATA_BLOB data;
    struct smb2_write *w;
    struct smb2_request **req;
    

    data = data_blob_talloc(tthrd->tt_tree, NULL, size);
    if (size != data.length) {
        torture_comment(tthrd->tt_tctx, "failed allocate blob\n");
        return ENOMEM;
    }
    memset(data.data, 0xab, size);

    
    w = talloc_zero_array(tthrd->tt_memctx, struct smb2_write, tthrd->tt_max_related);
    req = talloc_zero_array(tthrd->tt_memctx, struct smb2_request *, tthrd->tt_max_related);

    if (w == NULL || req == NULL)
    {
        torture_comment(tthrd->tt_tctx, "failed to allocate %p %p\n", w, req);
        return ENOMEM;
    }


    /* Ask for a lot of credit via 8 related, compound write requests 
     */
    for (j = 0; j < tthrd->tt_max_write && ret == 0; j++) {

        smb2_transport_credits_ask_num(tthrd->tt_tree->session->transport, 8192);
        smb2_transport_compound_start(tthrd->tt_tree->session->transport, 8);
        for (i = 0; i < tthrd->tt_max_related; i++) {
            ZERO_STRUCT(w[i]);
            w[i].in.file.handle = tthrd->tt_handle;
            w[i].in.offset      = (i * size) +  (j * tthrd->tt_max_write * size);
            w[i].in.data        = data;
    
            if (i != 0) {
                smb2_transport_compound_set_related(
                    tthrd->tt_tree->session->transport, true);
            }

            req[i] = smb2_write_send(tthrd->tt_tree, &w[i]);
        }

        torture_comment(tthrd->tt_tctx, "%d:%d writing %s from %ld to %ld\n",
            tthrd->tt_id, tthrd->tt_pid, tthrd->tt_fname, w[0].in.offset, 
            w[tthrd->tt_max_related - 1].in.offset + size);

        for (i = 0; i < tthrd->tt_max_related && ret == 0; i++)
        {
            status = smb2_write_recv(req[i], &w[i]);
            if (!NT_STATUS_EQUAL(status, NT_STATUS_OK))
            {
                torture_result(tthrd->tt_tctx, TORTURE_FAIL, __location__
                    ": %d:%d Incorrect status %s - should be %s",
                    tthrd->tt_id, tthrd->tt_pid,
                    nt_errstr(status), nt_errstr(NT_STATUS_OK));

                ret = EBADF;
            }
        }
    }
done:
    return ret;
}

#undef sprintf

bool run_credit_exhaust(struct torture_context *tctx, 
        struct smb2_tree *tree,
        int max_jobs,
        int max_related,
        int max_writes)
{
    bool            result = true;
    int         i;
    NTSTATUS        status;
    int         child_status;
    pid_t           pid;
    tthrd_ctx       thrd_data;
    int         num_child = 0;
    

    /* not threads 
     */
    for (i = 0; i < max_jobs && result == true; i++)
    {
        if ((pid = fork()) == 0)
        {
            int exit_code = 0;

            thrd_data.tt_id = i;
            thrd_data.tt_pid = getpid();
            thrd_data.tt_max_related = max_related;
            thrd_data.tt_max_write = max_writes;
            thrd_data.tt_tctx = tctx;
            thrd_data.tt_memctx = talloc_new(tctx);

            torture_comment(tctx, "%d:%d connecting\n", 
                thrd_data.tt_id, thrd_data.tt_pid);

            if (!torture_smb2_connection(thrd_data.tt_tctx, &thrd_data.tt_tree))
            {
                torture_comment(tctx, "%d:%d failed to connect", 
                    thrd_data.tt_id, thrd_data.tt_pid);

                exit(EINVAL);
            }

            sprintf(thrd_data.tt_fname, "credit_hog_%d", i);
            smb2_util_unlink(thrd_data.tt_tree, thrd_data.tt_fname);

            torture_comment(tctx, "%d:%d creating %s\n", 
                thrd_data.tt_id, thrd_data.tt_pid, thrd_data.tt_fname);

            thrd_data.tt_handle = torture_smb2_createfile(thrd_data.tt_tree,
                            thrd_data.tt_fname);

            torture_comment(tctx, "%d:%d writing %s\n", 
                 thrd_data.tt_id, thrd_data.tt_pid, thrd_data.tt_fname);

            if ((exit_code = writex(&thrd_data)) != 0)
            {
                torture_comment(tctx, "%d:%d failed %d\n",
                    thrd_data.tt_id, thrd_data.tt_pid, exit_code);
            }

            torture_comment(tctx, "disconnecting %d\n", i);
            torture_smb2_close(thrd_data.tt_tree,  thrd_data.tt_handle);
            smb2_logoff(thrd_data.tt_tree->session);
            talloc_free(thrd_data.tt_memctx);

            exit(exit_code);
        }

        if (pid == -1)
        {
            torture_comment(tctx, "fork %d failed\n", i);
        }
        else
        {
            num_child++;
        }
    }

    while (num_child && result == true)
    {
        child_status = 0;
        if ((pid = waitpid(-1, &child_status, 0)) == -1)
        {
            torture_comment(tctx, "waitpid() failed, errno %d\n", errno);
            result = false;
        }
        else
        {
            torture_comment(tctx, "child %d done, status %d\n", 
                pid, WEXITSTATUS(child_status));

            num_child--;
        }
    }
    
    return result;
}

bool run_write_parallel(struct torture_context *tctx, 
        struct smb2_tree *tree,
	char *fname,
	char *dname,
        int max_jobs,
        long writesize,
        long filesize,
	double *msec_out)
{
    bool        result = true;
    bool        ret = true;
    int         i = 0;
    int         num_child = 0;
    int         child_status = 0;
    int         nwrites = filesize / writesize;
    double      t0, t1;

    offset_t        off;
    struct timespec ts;
    tthrd_ctx       thrd_data;
    pid_t           pid;
    NTSTATUS        status;
    struct smb2_handle hdir;
    struct smb2_create io;
    struct smb2_close cio;
    struct smb2_write w;

    status = torture_smb2_testdir(tree, dname, &hdir);
    torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

    torture_comment(tctx, "Simulated Parallel Writes.\n"
                          "%d jobs, %ld write size, %ld file size, "
			  "%d nwrites\n",
                          max_jobs, writesize, filesize, nwrites);

    /*
     * Fork a bunch of processes
     */
    for (i = 0; i < max_jobs && result == true; i++)
    {
        if ((pid = fork())== 0)
        {
            int exit_code = 0;

	    char *buf;
	    buf = malloc(sizeof(char) * writesize);
	    char time_filename[MAX_WRITE];

            thrd_data.tt_id = i;
            thrd_data.tt_pid = getpid();
            thrd_data.tt_tctx = tctx;
            thrd_data.tt_memctx = talloc_new(tctx);

            torture_comment(tctx, "%d:%d connecting\n", 
                thrd_data.tt_id, thrd_data.tt_pid);

            if (!torture_smb2_connection(thrd_data.tt_tctx, &thrd_data.tt_tree))
            {
                torture_comment(tctx, "%d:%d failed to connect", 
                    thrd_data.tt_id, thrd_data.tt_pid);

                exit(EINVAL);
            }

            sprintf(thrd_data.tt_fname, "%s\\%s%d", dname, fname, i);
	    sprintf(time_filename, "/tmp/p_w_time_%d", i);
            sprintf(buf, "parallel_write_payload_%d\n", i);

	    ZERO_STRUCT(io);
	    io.in.oplock_level = 0;
	    io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	    io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	    io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	    io.in.share_access = 
		    NTCREATEX_SHARE_ACCESS_DELETE|
		    NTCREATEX_SHARE_ACCESS_READ|
		    NTCREATEX_SHARE_ACCESS_WRITE;
	    io.in.create_options = NTCREATEX_OPTIONS_WRITE_THROUGH;
	    io.in.fname = thrd_data.tt_fname;

            smb2_util_unlink(thrd_data.tt_tree, thrd_data.tt_fname);

            torture_comment(tctx, "%d:%d creating %s\n",
                    thrd_data.tt_id, thrd_data.tt_pid, thrd_data.tt_fname);

	    status = smb2_create(thrd_data.tt_tree, thrd_data.tt_memctx, &io);
	    thrd_data.tt_handle = io.out.file.handle;

            torture_comment(tctx, "%d:%d writing %s {%d:%ldk:%ldM}\n",
                    thrd_data.tt_id, thrd_data.tt_pid, thrd_data.tt_fname,
		    max_jobs, writesize / (1 << 10), filesize / (1 << 20));

            clock_gettime(CLOCK_MONOTONIC, &ts);
            t0 = (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;

            /*
             * Do a bunch of writing!
             */
            for (int j = 0, off = 0; j < nwrites; j++, off += writesize)
            {
		ZERO_STRUCT(w);
		w.in.file.handle = thrd_data.tt_handle;
		w.in.offset = off;
		w.in.data = data_blob_talloc(thrd_data.tt_memctx, NULL, sizeof(buf));
		for(int k = 0; k < sizeof(buf); k++) {
		    w.in.data.data[k] = buf[k];
		}

		//torture_comment(tctx, "writing %d, offset %d\n", j, off);

		status = smb2_write(thrd_data.tt_tree, &w);
            }

            clock_gettime(CLOCK_MONOTONIC, &ts);
            t1 = (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
            t1 = t1 - t0;

            thrd_data.tt_msec = (filesize / t1) / (1 << 20);

            torture_comment(tctx, "disconnecting %d\n", i);

	    ZERO_STRUCT(cio);
	    cio.in.file.handle 	= thrd_data.tt_handle;
	    cio.in.flags	= SMB2_CLOSE_FLAGS_FULL_INFORMATION;
	    status		= smb2_close(thrd_data.tt_tree, &cio);

            smb2_logoff(thrd_data.tt_tree->session);
            talloc_free(thrd_data.tt_memctx);
            torture_comment(tctx, "%d:%d >>> %12f MB/s\n", thrd_data.tt_id,
                    thrd_data.tt_pid, thrd_data.tt_msec);
	    FILE* fp = fopen(time_filename, "w");
	    if(fp) {
		fprintf(fp, "%lf", thrd_data.tt_msec);
	    }
	    fclose(fp);
	    free(buf);

            exit(exit_code);
        }

        if(pid == -1)
        {
            torture_comment(tctx, "fork %d failed\n", i);
        }
        else
        {
            num_child++;
        }
    }

    while (num_child && result == true)
    {
        child_status = 0;

        if ((pid = waitpid(-1, &child_status, 0)) == -1)
        {
            torture_comment(tctx, "waitpid() failed, errno %d\n", errno);
            result = false;
        }
        else
        {
            torture_comment(tctx, "child %d done, status %d\n",
                    pid, WEXITSTATUS(child_status));
            num_child--;
        }
    }

    double total_msec = 0.0;
    char agg_file[MAX_WRITE];
    FILE* pFile;
    for(int j = 0; j < max_jobs; j++) {
	double msec_tmp = 0.0;
	sprintf(agg_file, "/tmp/p_w_time_%d", j);
	pFile = fopen(agg_file, "r");
	if (pFile == NULL) {
	    torture_comment(tctx, "Problem aggregating data\n");
	    continue;
	}
	fscanf(pFile, "%lf", &msec_tmp);
	total_msec += msec_tmp;
	fclose(pFile);
    }
    *msec_out = total_msec;

done:

    return result;
}

bool test_credit_exhaust_16(struct torture_context *tctx, 
        struct smb2_tree *tree)
{
    return run_credit_exhaust(tctx, tree, 16, 8, 1024); 
}

bool test_credit_exhaust_64(struct torture_context *tctx, 
        struct smb2_tree *tree)
{
    return run_credit_exhaust(tctx, tree, 64, 8, 2048); 
}

bool test_credit_exhaust_128(struct torture_context *tctx, 
        struct smb2_tree *tree)
{
    return run_credit_exhaust(tctx, tree, 128, 8, 1024); 
}

// Simulate parallel writers, using different numbers of workers, block
// sizes, filesizes
bool sim_write_parallel(struct torture_context *tctx,
	struct smb2_tree *tree)
{
    bool ret = true;
    double* msecs;

    struct w_params {
	int nworkers;
	long wsize;
	long fsize;
    } wperf_permutations[] = {
	{1,  (1 << 10),  8 * (1 << 20)},
	{1,  (1 << 12),  8 * (1 << 20)},
	{1,  (1 << 14),  8 * (1 << 20)},
	{1,  (1 << 16),  8 * (1 << 20)},
	{1,  (1 << 18),  8 * (1 << 20)},
	{1,  (1 << 20),  8 * (1 << 20)},

	{2,  (1 << 10),  8 * (1 << 20)},
	{2,  (1 << 12),  8 * (1 << 20)},
	{2,  (1 << 14),  8 * (1 << 20)},
	{2,  (1 << 16),  8 * (1 << 20)},
	{2,  (1 << 18),  8 * (1 << 20)},
	{2,  (1 << 20),  8 * (1 << 20)},

	{64,  (1 << 20), 1 * (1 << 30)}
    };

    msecs = malloc(sizeof(double) * ARRAY_SIZE(wperf_permutations));
    memset(msecs, 0, sizeof(double) * ARRAY_SIZE(msecs));

    for (int i = 0; i < ARRAY_SIZE(wperf_permutations); i++)
    {
	ret &= run_write_parallel(tctx, tree, "parallel_write_",
			"sim_parallel_write",
			wperf_permutations[i].nworkers,
			wperf_permutations[i].wsize,
			wperf_permutations[i].fsize,
			&msecs[i]);
	if (!ret) {
	    break;
	}
    }
    for (int i = 0; i < ARRAY_SIZE(wperf_permutations); i++)
    {
    	torture_comment(tctx, "{{%4d:%4ldk:%4ldM}} = %12f MB/s\n",
		wperf_permutations[i].nworkers,
		wperf_permutations[i].wsize / (1 << 10),
		wperf_permutations[i].fsize / (1 << 20),
		msecs[i]);
    }

    free(msecs);
    return ret;
}

// Simulate parallel reads
// Dependent on running the write call first
bool run_read_parallel(struct torture_context *tctx, 
        struct smb2_tree *tree,
	char *fname,
	char *dname,
        int max_jobs,
	double *msec_out)
{
    bool        result = true;
    bool        ret = true;
    int         i = 0;
    int         num_child = 0;
    int         child_status = 0;
    double      t0, t1;
    double	fakemsec;

    offset_t        off;
    struct timespec ts;
    tthrd_ctx       thrd_data;
    pid_t           pid;
    NTSTATUS        status;
    struct smb2_handle hdir;
    struct smb2_create io;
    struct smb2_close cio;
    struct smb2_read rd;



    status = torture_smb2_testdir(tree, dname, &hdir);
    torture_assert_ntstatus_ok(tctx, status, "Error creating directory");

    torture_comment(tctx, "Simulated Parallel Reads.\n"
                          "%d jobs", max_jobs);

    // First we have to create the files to be read!  Call the
    // run_write_parallel function to do this
    ret &= run_write_parallel(tctx, tree, fname,
		    dname,
		    64, (1 << 20), (1 << 30), &fakemsec);

    if (!ret)
	return ret;

    /*
     * Fork a bunch of processes
     */
    for (i = 0; i < max_jobs && result == true; i++)
    {
        if ((pid = fork())== 0)
        {
            int exit_code = 0;

	    char *buf;
	    char time_filename[MAX_WRITE];

            thrd_data.tt_id = i;
            thrd_data.tt_pid = getpid();
            thrd_data.tt_tctx = tctx;
            thrd_data.tt_memctx = talloc_new(tctx);

            torture_comment(tctx, "%d:%d connecting\n", 
                thrd_data.tt_id, thrd_data.tt_pid);

            if (!torture_smb2_connection(thrd_data.tt_tctx, &thrd_data.tt_tree))
            {
                torture_comment(tctx, "%d:%d failed to connect", 
                    thrd_data.tt_id, thrd_data.tt_pid);

                exit(EINVAL);
            }

            sprintf(thrd_data.tt_fname, "%s\\%s%d", dname, fname, i);
	    sprintf(time_filename, "/tmp/p_r_time_%d", i);
            sprintf(buf, "parallel_read_payload_%d\n", i);

	    ZERO_STRUCT(io);
	    io.in.oplock_level = 0;
	    io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	    io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	    io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	    io.in.share_access = 
		    NTCREATEX_SHARE_ACCESS_DELETE|
		    NTCREATEX_SHARE_ACCESS_READ|
		    NTCREATEX_SHARE_ACCESS_WRITE;
	    io.in.create_options = NTCREATEX_OPTIONS_WRITE_THROUGH;
	    io.in.fname = thrd_data.tt_fname;

            smb2_util_unlink(thrd_data.tt_tree, thrd_data.tt_fname);

            smb2_logoff(thrd_data.tt_tree->session);
            talloc_free(thrd_data.tt_memctx);
            torture_comment(tctx, "%d:%d >>> %12f MB/s\n", thrd_data.tt_id,
                    thrd_data.tt_pid, thrd_data.tt_msec);
	    FILE* fp = fopen(time_filename, "w");
	    if(fp) {
		fprintf(fp, "%lf", thrd_data.tt_msec);
	    }
	    fclose(fp);
	    free(buf);

            exit(exit_code);
        }

        if(pid == -1)
        {
            torture_comment(tctx, "fork %d failed\n", i);
        }
        else
        {
            num_child++;
        }
    }

    while (num_child && result == true)
    {
        child_status = 0;

        if ((pid = waitpid(-1, &child_status, 0)) == -1)
        {
            torture_comment(tctx, "waitpid() failed, errno %d\n", errno);
            result = false;
        }
        else
        {
            torture_comment(tctx, "child %d done, status %d\n",
                    pid, WEXITSTATUS(child_status));
            num_child--;
        }
    }

    double total_msec = 0.0;
    char agg_file[MAX_WRITE];
    FILE* pFile;
    for(int j = 0; j < max_jobs; j++) {
	double msec_tmp = 0.0;
	sprintf(agg_file, "/tmp/p_r_time_%d", j);
	pFile = fopen(agg_file, "r");
	if (pFile == NULL) {
	    torture_comment(tctx, "Problem aggregating data\n");
	    continue;
	}
	fscanf(pFile, "%lf", &msec_tmp);
	total_msec += msec_tmp;
	fclose(pFile);
    }
    *msec_out = total_msec;

done:

    return result;
}

// Simulate parallel readers
bool sim_read_parallel(struct torture_context *tctx,
	struct smb2_tree *tree)
{
    bool ret = true;
    double* msecs;

    struct r_params {
	int nworkers;
    } rperf_permutations[] = {
	{1},
	{2},
	{64}
    };

    msecs = malloc(sizeof(double) * ARRAY_SIZE(rperf_permutations));
    memset(msecs, 0, sizeof(double) * ARRAY_SIZE(msecs));

    for (int i = 0; i < ARRAY_SIZE(rperf_permutations); i++)
    {
	ret &= run_read_parallel(tctx, tree, "parallel_read_",
			"sim_parallel_read",
			rperf_permutations[i].nworkers,
			&msecs[i]);
	if (!ret) {
	    break;
	}
    }
    for (int i = 0; i < ARRAY_SIZE(rperf_permutations); i++)
    {
    	torture_comment(tctx, "{{%4d::}} = %12f MB/s\n",
		rperf_permutations[i].nworkers,
		msecs[i]);
    }

    free(msecs);
    return ret;
}

struct torture_suite *torture_smb2_spectra_init(void)
{
    struct torture_suite *suite =
        torture_suite_create(talloc_autofree_context(), "spectra");

    torture_suite_add_1smb2_test(suite, "credit_exhaust_16", test_credit_exhaust_16);
    torture_suite_add_1smb2_test(suite, "credit_exhaust_64", test_credit_exhaust_64);
    torture_suite_add_1smb2_test(suite, "credit_exhaust_128", test_credit_exhaust_128);
    torture_suite_add_1smb2_test(suite, "sim_write_parallel", sim_write_parallel);
    //torture_suite_add_1smb2_test(suite, "sim_read_parallel", sim_read_parallel);

    suite->description = talloc_strdup(suite, "Spectra logic likewise tests");
    return suite;
}
