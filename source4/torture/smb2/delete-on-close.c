/*
   Unix SMB/CIFS implementation.

   test delete-on-close in more detail

   Copyright (C) Richard Sharpe, 2013

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
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"

#define DNAME "test_dir"
#define FNAME DNAME "\\test_create.dat"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect status %s - should be %s\n", \
			 __location__, nt_errstr(status), nt_errstr(correct)); \
		return false; \
	}} while (0)

static bool create_dir(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle handle;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig;
	const char *owner_sid;
	uint32_t perms = 0;

	torture_comment(tctx, "Creating Directory for testing: %s\n", DNAME);

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access =
		SEC_STD_READ_CONTROL |
		SEC_STD_WRITE_DAC |
		SEC_STD_WRITE_OWNER;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = DNAME;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	/*
	 * We create an SD that allows us to do most things but we do not
	 * get DELETE and DELETE CHILD access!
	 */

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_OWNER |
		SEC_STD_WRITE_DAC | SEC_STD_READ_CONTROL | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_TRAVERSE | SEC_DIR_WRITE_EA | 
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA | SEC_FILE_READ_DATA;

	torture_comment(tctx, "Setting permissions on dir to 0x1e01bf\n");
	sd = security_descriptor_dacl_create(tctx,
					0, owner_sid, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					perms,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, handle);

	return true;
}

static bool set_dir_delete_perms(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle handle;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd, *sd_orig;
	const char *owner_sid;
	uint32_t perms = 0;

	torture_comment(tctx, "Opening Directory for setting new SD: %s\n", DNAME);

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access =
		SEC_STD_READ_CONTROL |
		SEC_STD_WRITE_DAC |
		SEC_STD_WRITE_OWNER;
	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = DNAME;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	/*
	 * We create an SD that allows us to do most things including
	 * get DELETE and DELETE CHILD access!
	 */

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_OWNER |
		SEC_STD_WRITE_DAC | SEC_STD_READ_CONTROL | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_TRAVERSE | SEC_DIR_WRITE_EA | 
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA |
		SEC_DIR_DELETE_CHILD | SEC_STD_DELETE |
		SEC_FILE_WRITE_DATA | SEC_FILE_READ_DATA;

	torture_comment(tctx, "Setting permissions on dir to 0x%0x\n", perms);
	sd = security_descriptor_dacl_create(tctx,
					0, owner_sid, NULL,
					owner_sid,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					perms,
					0,
					NULL);

	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = handle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, handle);

	return true;
}

static bool test_doc_overwrite_if(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on non-existent file (OVERWRITE_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	return true;
}

static bool test_doc_overwrite_if_exist(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	/* And set the SEC Descriptor appropriately */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on existing file (OVERWRITE_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_ACCESS_DENIED\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	/* First, create this file ... */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0x0;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Next, try to open it for Delete On Close */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	status = smb2_util_close(tree, io.out.file.handle);

	return true;
}

static bool test_doc_create(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on non-existent file (CREATE) \n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	return true;
}

static bool test_doc_create_exist(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on non-existent file (CREATE) \n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_COLLISION\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	/* First, create the file */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0x0;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Next, try to open it for Delete on Close */
	status = smb2_util_close(tree, io.out.file.handle);
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_COLLISION);

	status = smb2_util_close(tree, io.out.file.handle);

	return true;
}

static bool test_doc_create_if(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on non-existent file (OPEN_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	return true;
}

static bool test_doc_create_if_exist(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t perms = 0;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	torture_comment(tctx, "Create file with DeleteOnClose on existing file (OPEN_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_ACCESS_DENIED\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	/* Create the file first */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0x0;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Now try to create it for delete on close */
	ZERO_STRUCT(io);
	io.in.desired_access	 = 0x130196;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	status = smb2_util_close(tree, io.out.file.handle);

	return true;
}

/*
 * Test that parent directory open's share flags do not influence
 * file delete on close behavior.
 *
 * PART 1: Testing of delete on close when opening parent dir with
 *         no delete access and write sharing allowed.  The create
 *         should succeed without error. 
 */
static bool test_doc_parent_share_write(struct torture_context *tctx, struct smb2_tree *tree)
{
	bool ret = true;
	uint32_t perms = 0;
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle dh;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	set_dir_delete_perms(tctx, tree);

	torture_comment(tctx, "Open parent directory with SHARE_WRITE\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.out.file.handle;

	torture_comment(tctx, "Create non-existent file (OPEN_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = 0;
	io.in.create_options     = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "Re-open file with DeleteOnClose (OPEN_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	torture_comment(tctx, "Closing directory\n");

	status = smb2_util_close(tree, dh);

	return ret;
}

/*
 * Test that parent directory open's share flags do not influence
 * file delete on close behavior.
 *
 * PART 2: Testing of delete on close when opening parent dir with
 *         no delete access and no write sharing allowed.  The create
 *         should succeed without error.
 */
static bool test_doc_parent_no_share_write(struct torture_context *tctx, struct smb2_tree *tree)
{
	bool ret = true;
	uint32_t perms = 0;
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle dh;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	create_dir(tctx, tree);

	set_dir_delete_perms(tctx, tree);

	torture_comment(tctx, "Open parent directory without SHARE_WRITE\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.out.file.handle;

	torture_comment(tctx, "Create non-existent file (OPEN_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = 0;
	io.in.create_options     = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "Re-open file with DeleteOnClose (OPEN_IF)\n");
	torture_comment(tctx, "We expect NT_STATUS_OK\n");

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	torture_comment(tctx, "Closing directory\n");
	status = smb2_util_close(tree, dh);
	return ret;
}

/*
 * Test that a directory's delete on close flag is ignored if the directory
 * is not empty at the time of open.
 *
 * PART 1: Add a file to the directory. Open directory with delete on close.
 *         Close directory handle. Directory should not be deleted.
 */
static bool test_doc_directory(struct torture_context *tctx, struct smb2_tree *tree)
{
	bool ret = true;
	uint32_t perms = 0;
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle dh;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	torture_comment(tctx, "Create directory.\n");

	create_dir(tctx, tree);

	set_dir_delete_perms(tctx, tree);

	torture_comment(tctx, "Add a file.\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = 0;
	io.in.create_options     = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "Open directory with DELETE_ON_CLOSE\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Close directory handle.\n");
	status = smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "Re-open directory. We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);

	return ret;
}

/*
 * Test that a directory's delete on close flag is ignored if the directory
 * is not empty at the time of open.
 *
 * PART 2: Add a file to the directory, open directory for delete, delete
 *         child file, close directory handle.  Directory should not be
 *         deleted.
 */
static bool test_doc_directory2(struct torture_context *tctx, struct smb2_tree *tree)
{
	bool ret = true;
	uint32_t perms = 0;
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle dh;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	torture_comment(tctx, "Create directory.\n");

	create_dir(tctx, tree);

	set_dir_delete_perms(tctx, tree);

	torture_comment(tctx, "Add a file.\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = 0;
	io.in.create_options     = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "Open directory with DELETE_ON_CLOSE\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.out.file.handle;

	torture_comment(tctx, "Delete file..\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC | SEC_STD_DELETE |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	torture_comment(tctx, "Close directory handle.\n");
	status = smb2_util_close(tree, dh);

	torture_comment(tctx, "Re-open directory. We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);

	return ret;
}

/*
 * Test that a directory's delete on close flag is ignored if the directory
 * is not empty at the time of open.
 *
 * PART 3: Add a file to the directory, open file with delete on close,
 *         open directory with delete on close, close file handle (file
 *         is now deleted), close directory handle.  Directory should not
 *         be deleted.
 */
static bool test_doc_directory3(struct torture_context *tctx, struct smb2_tree *tree)
{
	bool ret = true;
	uint32_t perms = 0;
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle dh;
	struct smb2_handle fh;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	torture_comment(tctx, "Create directory.\n");

	create_dir(tctx, tree);

	set_dir_delete_perms(tctx, tree);

	torture_comment(tctx, "Add a file.\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = 0;
	io.in.create_options     = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "Open file delete on close, but do not close\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC | SEC_STD_DELETE |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fh = io.out.file.handle;

	torture_comment(tctx, "Open directory with DELETE_ON_CLOSE\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.out.file.handle;

	torture_comment(tctx, "Close file handle.\n");
	status = smb2_util_close(tree, fh);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	torture_comment(tctx, "Close directory handle.\n");
	status = smb2_util_close(tree, dh);

	torture_comment(tctx, "Re-open directory. We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);

	return ret;
}

/*
 * Test that a directory's delete on close flag is ignored if the directory
 * is not empty at the time of open.
 *
 * PART 4: Add a file to the directory, open file, open file again with
 *         delete on close, close second file handle (file now "delete
 *         pending"), open directory with delete on close, close first
 *         file handle (file is now deleted), close directory handle.
 *         Directory should not be deleted.
 */
static bool test_doc_directory4(struct torture_context *tctx, struct smb2_tree *tree)
{
	bool ret = true;
	uint32_t perms = 0;
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_handle dh;
	struct smb2_handle fh;

	/* File should not exist for this first test, so make sure */
	set_dir_delete_perms(tctx, tree);

	smb2_deltree(tree, DNAME);

	torture_comment(tctx, "Create directory.\n");

	create_dir(tctx, tree);

	set_dir_delete_perms(tctx, tree);

	torture_comment(tctx, "Add a file.\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_READ_CONTROL | SEC_STD_DELETE | 
		SEC_DIR_WRITE_ATTRIBUTE | SEC_DIR_READ_ATTRIBUTE | 
		SEC_DIR_WRITE_EA | SEC_FILE_APPEND_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access	 = 0;
	io.in.create_options     = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "Open file share delete, but do not close\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC | SEC_STD_DELETE |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE |
				   NTCREATEX_SHARE_ACCESS_READ |
				   NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options     = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fh = io.out.file.handle;

	torture_comment(tctx, "Open file delete on close, and close\n");

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE |
				   NTCREATEX_SHARE_ACCESS_READ |
				   NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options     = NTCREATEX_OPTIONS_DELETE_ON_CLOSE | 
				   NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.fname              = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "Open directory with DELETE_ON_CLOSE\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);
	dh = io.out.file.handle;

	torture_comment(tctx, "Close first file handle.\n");
	status = smb2_util_close(tree, fh);

	/* Check it was deleted */
	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.file_attributes	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access	 = NTCREATEX_SHARE_ACCESS_DELETE |
				   NTCREATEX_SHARE_ACCESS_READ |
				   NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options     = 0;
	io.in.fname              = FNAME;

	torture_comment(tctx, "Testing if the file was deleted when closed\n");
	torture_comment(tctx, "We expect NT_STATUS_OBJECT_NAME_NOT_FOUND\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	torture_comment(tctx, "Close directory handle.\n");
	status = smb2_util_close(tree, dh);

	torture_comment(tctx, "Re-open directory. We expect NT_STATUS_OK\n");

	perms = SEC_STD_SYNCHRONIZE | SEC_STD_WRITE_DAC |
		SEC_STD_READ_CONTROL | SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE | SEC_FILE_WRITE_EA |
		SEC_FILE_READ_EA | SEC_FILE_APPEND_DATA | SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;

	ZERO_STRUCT(io);
	io.in.desired_access	 = perms;
	io.in.create_options	 = NTCREATEX_OPTIONS_DIRECTORY;
	io.in.file_attributes	 = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access	 = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname		 = DNAME;

	status = smb2_create(tree, tctx, &(io));
	CHECK_STATUS(status, NT_STATUS_OK);

	return ret;
}
/*
 *  Extreme testing of Delete On Close and permissions
 */
struct torture_suite *torture_smb2_doc_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "delete-on-close-perms");

	torture_suite_add_1smb2_test(suite, "OVERWRITE_IF", test_doc_overwrite_if);
	torture_suite_add_1smb2_test(suite, "OVERWRITE_IF Existing", test_doc_overwrite_if_exist);
	torture_suite_add_1smb2_test(suite, "CREATE", test_doc_create);
	torture_suite_add_1smb2_test(suite, "CREATE Existing", test_doc_create_exist);
	torture_suite_add_1smb2_test(suite, "CREATE_IF", test_doc_create_if);
	torture_suite_add_1smb2_test(suite, "CREATE_IF Existing", test_doc_create_if_exist);
	torture_suite_add_1smb2_test(suite, "parent_open_share_write", test_doc_parent_share_write);
	torture_suite_add_1smb2_test(suite, "parent_open_no_share_write", test_doc_parent_no_share_write);
	torture_suite_add_1smb2_test(suite, "directory", test_doc_directory);
	torture_suite_add_1smb2_test(suite, "directory2", test_doc_directory2);
	torture_suite_add_1smb2_test(suite, "directory3", test_doc_directory3);
	torture_suite_add_1smb2_test(suite, "directory4", test_doc_directory4);

	suite->description = talloc_strdup(suite, "SMB2-Delete-on-Close-Perms tests");

	return suite;
}
