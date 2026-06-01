/*
 * Copyright (C) 2026 The pgmoneta community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <pgmoneta.h>
#include <logging.h>
#include <network.h>
#include <security.h>
#include <server.h>
#include <tsclient.h>
#include <tscommon.h>
#include <mctf.h>

#include <openssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void pgmoneta_test_cleanup_ssl(SSL** ssl);
static void pgmoneta_test_cleanup_socket(int* socket);
static void pgmoneta_test_cleanup_connection(SSL** ssl, int* socket);
static void pgmoneta_test_cleanup_query_response(struct query_response** qr);

MCTF_TEST(test_pgmoneta_restored_backup_start)
{
   SSL* custom_user_ssl = NULL;
   int custom_user_socket = -1;
   struct query_response* qr = NULL;
   int restored_port = -1;
   char command[2048];
   char* output = NULL;
   int exit_code = 0;
   const char* version = NULL;

   pgmoneta_test_setup();

   /* --- seed data on primary --- */
   MCTF_ASSERT(pgmoneta_server_authenticate(PRIMARY_SERVER, "mydb", "myuser", "mypass", false,
                                            &custom_user_ssl, &custom_user_socket) == 0,
               cleanup, "failed to authenticate with custom user - check user configuration");

   MCTF_ASSERT(pgmoneta_test_execute_query(PRIMARY_SERVER, custom_user_ssl, custom_user_socket,
                                           "DROP TABLE IF EXISTS restore_check;", &qr) == 0,
               cleanup, "failed to drop existing table");
   pgmoneta_test_cleanup_query_response(&qr);

   MCTF_ASSERT(pgmoneta_test_execute_query(PRIMARY_SERVER, custom_user_ssl, custom_user_socket,
                                           "CREATE TABLE restore_check (id int);", &qr) == 0,
               cleanup, "failed to create table");
   pgmoneta_test_cleanup_query_response(&qr);

   MCTF_ASSERT(pgmoneta_test_execute_query(PRIMARY_SERVER, custom_user_ssl, custom_user_socket,
                                           "INSERT INTO restore_check VALUES (1), (2), (3);", &qr) == 0,
               cleanup, "failed to insert data");
   pgmoneta_test_cleanup_query_response(&qr);

   /* --- backup and restore --- */
   MCTF_ASSERT(pgmoneta_test_add_backup() == 0, cleanup,
               "backup failed - check server is online and backup configuration");

   MCTF_ASSERT(pgmoneta_tsclient_restore("primary", "newest", "current", 0) == 0, cleanup,
               "restore operation failed");

   /* --- start restored server in container --- */
   restored_port = start_restored_backup(TEST_RESTORE_DIR, RESTORED_BACKUP_DEFAULT_PORT);
   MCTF_ASSERT(restored_port > 0, cleanup, "failed to start restored backup container");

   /* --- verify row count via psql inside the container --- */
   version = getenv("TEST_PG_VERSION");
   if (version == NULL || version[0] == '\0')
   {
      version = "17";
   }

   pgmoneta_snprintf(command, sizeof(command),
                     "podman exec %s /usr/pgsql-%s/bin/psql "
                     "-U myuser -d mydb -tAc "
                     "\"SELECT count(*) FROM restore_check;\"",
                     "pgmoneta-test-restored-backup", version);

   MCTF_ASSERT(pgmoneta_test_exec_command(command, &output, &exit_code) == 0 && exit_code == 0,
               cleanup, "failed to run psql query inside restored container");

   MCTF_ASSERT(output != NULL && atoi(output) == 3,
               cleanup, "restored backup does not contain expected 3 rows");

cleanup:
   free(output);
   pgmoneta_test_cleanup_query_response(&qr);
   pgmoneta_test_cleanup_connection(&custom_user_ssl, &custom_user_socket);
   stop_restored_backup();
   pgmoneta_test_basedir_cleanup();
   pgmoneta_test_teardown();
   MCTF_FINISH();
}

static void
pgmoneta_test_cleanup_ssl(SSL** ssl)
{
   if (ssl != NULL && *ssl != NULL)
   {
      pgmoneta_close_ssl(*ssl);
      *ssl = NULL;
   }
}

static void
pgmoneta_test_cleanup_socket(int* socket)
{
   if (socket != NULL && *socket != -1)
   {
      pgmoneta_disconnect(*socket);
      *socket = -1;
   }
}

static void
pgmoneta_test_cleanup_connection(SSL** ssl, int* socket)
{
   pgmoneta_test_cleanup_ssl(ssl);
   pgmoneta_test_cleanup_socket(socket);
}

static void
pgmoneta_test_cleanup_query_response(struct query_response** qr)
{
   if (qr != NULL && *qr != NULL)
   {
      pgmoneta_free_query_response(*qr);
      *qr = NULL;
   }
}