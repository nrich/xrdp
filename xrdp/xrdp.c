/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2013
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * main program
 */

#include "xrdp.h"
#include "log.h"

#define THREAD_WAITING 100

static struct xrdp_listen *g_listen = 0;
static long g_threadid = 0; /* main threadid */

static long g_sync_mutex = 0;
static long g_sync1_mutex = 0;
static tbus g_term_event = 0;
static tbus g_sync_event = 0;
/* syncronize stuff */
static int g_sync_command = 0;
static long g_sync_result = 0;
static long g_sync_param1 = 0;
static long g_sync_param2 = 0;
static long (*g_sync_func)(long param1, long param2);

/*****************************************************************************/
/* This function is used to run a function from the main thread.
   Sync_func is the function pointer that will run from main thread
   The function can have two long in parameters and must return long */
long APP_CC
g_xrdp_sync(long (*sync_func)(long param1, long param2), long sync_param1,
            long sync_param2)
{
    long sync_result;
    int sync_command;

    /* If the function is called from the main thread, the function can
     * be called directly. g_threadid= main thread ID*/
    if (tc_threadid_equal(tc_get_threadid(), g_threadid))
    {
        /* this is the main thread, call the function directly */
        /* in fork mode, this always happens too */
        sync_result = sync_func(sync_param1, sync_param2);
        /*g_writeln("g_xrdp_sync processed IN main thread -> continue");*/
    }
    else
    {
        /* All threads have to wait here until the main thread
         * process the function. g_process_waiting_function() is called
         * from the listening thread. g_process_waiting_function() process the function*/
        tc_mutex_lock(g_sync1_mutex);
        tc_mutex_lock(g_sync_mutex);
        g_sync_param1 = sync_param1;
        g_sync_param2 = sync_param2;
        g_sync_func = sync_func;
        /* set a value THREAD_WAITING so the g_process_waiting_function function
         * know if any function must be processed */
        g_sync_command = THREAD_WAITING;
        tc_mutex_unlock(g_sync_mutex);
        /* set this event so that the main thread know if
         * g_process_waiting_function() must be called */
        g_set_wait_obj(g_sync_event);

        do
        {
            g_sleep(100);
            tc_mutex_lock(g_sync_mutex);
            /* load new value from global to see if the g_process_waiting_function()
             * function has processed the function */
            sync_command = g_sync_command;
            sync_result = g_sync_result;
            tc_mutex_unlock(g_sync_mutex);
        }
        while (sync_command != 0); /* loop until g_process_waiting_function()

                                * has processed the request */
        tc_mutex_unlock(g_sync1_mutex);
        /*g_writeln("g_xrdp_sync processed BY main thread -> continue");*/
    }

    return sync_result;
}

/*****************************************************************************/
void DEFAULT_CC
xrdp_shutdown(int sig)
{
    tbus threadid;

    threadid = tc_get_threadid();
    g_writeln("shutting down");
    g_writeln("signal %d threadid %p", sig, threadid);

    if (!g_is_wait_obj_set(g_term_event))
    {
        g_set_wait_obj(g_term_event);
    }
}

/*****************************************************************************/
void DEFAULT_CC
xrdp_child(int sig)
{
    g_waitchild();
}

/*****************************************************************************/
/* called in child just after fork */
int APP_CC
xrdp_child_fork(void)
{
    int pid;
    char text[256];

    /* close, don't delete these */
    g_close_wait_obj(g_term_event);
    g_close_wait_obj(g_sync_event);
    pid = g_getpid();
    g_snprintf(text, 255, "xrdp_%8.8x_main_term", pid);
    g_term_event = g_create_wait_obj(text);
    g_snprintf(text, 255, "xrdp_%8.8x_main_sync", pid);
    g_sync_event = g_create_wait_obj(text);
    return 0;
}

/*****************************************************************************/
int DEFAULT_CC
g_is_term(void)
{
    return g_is_wait_obj_set(g_term_event);
}

/*****************************************************************************/
void APP_CC
g_set_term(int in_val)
{
    if (in_val)
    {
        g_set_wait_obj(g_term_event);
    }
    else
    {
        g_reset_wait_obj(g_term_event);
    }
}

/*****************************************************************************/
tbus APP_CC
g_get_term_event(void)
{
    return g_term_event;
}

/*****************************************************************************/
tbus APP_CC
g_get_sync_event(void)
{
    return g_sync_event;
}

/*****************************************************************************/
void DEFAULT_CC
pipe_sig(int sig_num)
{
    /* do nothing */
    g_writeln("got XRDP SIGPIPE(%d)", sig_num);
}

/*****************************************************************************/
/*Some function must be called from the main thread.
 if g_sync_command==THREAD_WAITING a function is waiting to be processed*/
void APP_CC
g_process_waiting_function(void)
{
    tc_mutex_lock(g_sync_mutex);

    if (g_sync_command != 0)
    {
        if (g_sync_func != 0)
        {
            if (g_sync_command == THREAD_WAITING)
            {
                g_sync_result = g_sync_func(g_sync_param1, g_sync_param2);
            }
        }

        g_sync_command = 0;
    }

    tc_mutex_unlock(g_sync_mutex);
}

/*****************************************************************************/
int APP_CC
xrdp_process_params(int argc, char **argv,
                    struct xrdp_startup_params *startup_params)
{
    int index;
    char option[128];
    char value[128];

    index = 1;

    while (index < argc)
    {
        g_strncpy(option, argv[index], 127);

        if (index + 1 < argc)
        {
            g_strncpy(value, argv[index + 1], 127);
        }
        else
        {
            value[0] = 0;
        }

        if ((g_strncasecmp(option, "-help", 255)) == 0 ||
                (g_strncasecmp(option, "--help", 255)) == 0 ||
                (g_strncasecmp(option, "-h", 255)) == 0)
        {
            startup_params->help = 1;
        }
        else if ((g_strncasecmp(option, "-kill", 255) == 0) ||
                 (g_strncasecmp(option, "--kill", 255) == 0) ||
                 (g_strncasecmp(option, "-k", 255) == 0))
        {
            startup_params->kill = 1;
        }
        else if ((g_strncasecmp(option, "-nodaemon", 255) == 0) ||
                 (g_strncasecmp(option, "--nodaemon", 255) == 0) ||
                 (g_strncasecmp(option, "-nd", 255) == 0) ||
                 (g_strncasecmp(option, "--nd", 255) == 0) ||
                 (g_strncasecmp(option, "-ns", 255) == 0) ||
                 (g_strncasecmp(option, "--ns", 255) == 0))
        {
            startup_params->no_daemon = 1;
        }
        else if ((g_strncasecmp(option, "-v", 255) == 0) ||
                 (g_strncasecmp(option, "--version", 255) == 0))
        {
            startup_params->version = 1;
        }
        else if ((g_strncasecmp(option, "-p", 255) == 0) ||
                 (g_strncasecmp(option, "--port", 255) == 0))
        {
            index++;
            g_strncpy(startup_params->port, value, 127);

            if (g_strlen(startup_params->port) < 1)
            {
                g_writeln("error processing params, port [%s]", startup_params->port);
                return 1;
            }
            else
            {
                g_writeln("--port parameter found, ini override [%s]",
                          startup_params->port);
            }
        }
        else if ((g_strncasecmp(option, "-f", 255) == 0) ||
                 (g_strncasecmp(option, "--fork", 255) == 0))
        {
            startup_params->fork = 1;
            g_writeln("--fork parameter found, ini override");
        }
        else
        {
            return 1;
        }

        index++;
    }

    return 0;
}

/*****************************************************************************/
int DEFAULT_CC
main(int argc, char **argv)
{
    int test;
    int host_be;
    char cfg_file[256];
    enum logReturns error;
    struct xrdp_startup_params *startup_params;
    int pid;
    int fd;
    int no_daemon;
    char text[256];
    char pid_file[256];

    g_init("xrdp");
    ssl_init();

    for (test = 0; test < argc; test++)
    {
        DEBUG(("Argument %i - %s", test, argv[test]));
    }

    /* check compiled endian with actual endian */
    test = 1;
    host_be = !((int)(*(unsigned char *)(&test)));
#if defined(B_ENDIAN)

    if (!host_be)
#endif
#if defined(L_ENDIAN)
        if (host_be)
#endif
        {
            g_writeln("endian wrong, edit arch.h");
            return 0;
        }

    /* check long, int and void* sizes */
    if (sizeof(int) != 4)
    {
        g_writeln("unusable int size, must be 4");
        return 0;
    }

    if (sizeof(long) != sizeof(void *))
    {
        g_writeln("long size must match void* size");
        return 0;
    }

    if (sizeof(long) != 4 && sizeof(long) != 8)
    {
        g_writeln("unusable long size, must be 4 or 8");
        return 0;
    }

    if (sizeof(tui64) != 8)
    {
        g_writeln("unusable tui64 size, must be 8");
        return 0;
    }

    g_snprintf(cfg_file, 255, "%s/xrdp.ini", XRDP_CFG_PATH);

    /* starting logging subsystem */
    error = log_start(cfg_file, "XRDP");

    if (error != LOG_STARTUP_OK)
    {
        switch (error)
        {
            case LOG_ERROR_MALLOC:
                g_writeln("error on malloc. cannot start logging. quitting.");
                break;
            case LOG_ERROR_FILE_OPEN:
                g_writeln("error opening log file [%s]. quitting.",
                          getLogFile(text, 255));
                break;
            default:
                g_writeln("log_start error");
                break;
        }

        g_deinit();
        g_exit(1);
    }

    startup_params = (struct xrdp_startup_params *)
                     g_malloc(sizeof(struct xrdp_startup_params), 1);

    if (xrdp_process_params(argc, argv, startup_params) != 0)
    {
        g_writeln("Unknown Parameter");
        g_writeln("xrdp -h for help");
        g_writeln("");
        g_deinit();
        g_exit(0);
    }

    g_snprintf(pid_file, 255, "%s/xrdp.pid", XRDP_PID_PATH);
    no_daemon = 0;

    if (startup_params->kill)
    {
        g_writeln("stopping xrdp");
        /* read the xrdp.pid file */
        fd = -1;

        if (g_file_exist(pid_file)) /* xrdp.pid */
        {
            fd = g_file_open(pid_file); /* xrdp.pid */
        }

        if (fd == -1)
        {
            g_writeln("problem opening to xrdp.pid [%s]", pid_file);
            g_writeln("maybe its not running");
        }
        else
        {
            g_memset(text, 0, 32);
            g_file_read(fd, text, 31);
            pid = g_atoi(text);
            g_writeln("stopping process id %d", pid);

            if (pid > 0)
            {
                g_sigterm(pid);
            }

            g_file_close(fd);
        }

        g_deinit();
        g_exit(0);
    }

    if (startup_params->no_daemon)
    {
        no_daemon = 1;
    }

    if (startup_params->help)
    {
        g_writeln("");
        g_writeln("xrdp: A Remote Desktop Protocol server.");
        g_writeln("Copyright (C) Jay Sorg 2004-2013");
        g_writeln("See http://xrdp.sourceforge.net for more information.");
        g_writeln("");
        g_writeln("Usage: xrdp [options]");
        g_writeln("   --help: show help");
        g_writeln("   --nodaemon: don't fork into background");
        g_writeln("   --kill: shut down xrdp");
        g_writeln("   --port: tcp listen port");
        g_writeln("   --fork: fork on new connection");
        g_writeln("");
        g_deinit();
        g_exit(0);
    }

    if (startup_params->version)
    {
        g_writeln("");
        g_writeln("xrdp: A Remote Desktop Protocol server.");
        g_writeln("Copyright (C) Jay Sorg 2004-2013");
        g_writeln("See http://xrdp.sourceforge.net for more information.");
        g_writeln("Version %s", PACKAGE_VERSION);
        g_writeln("");
        g_deinit();
        g_exit(0);
    }

    if (g_file_exist(pid_file)) /* xrdp.pid */
    {
        g_writeln("It looks like xrdp is allready running,");
        g_writeln("if not delete the xrdp.pid file and try again");
        g_deinit();
        g_exit(0);
    }

    if (!no_daemon)
    {

        /* make sure containing directory exists */
        g_create_path(pid_file);

        /* make sure we can write to pid file */
        fd = g_file_open(pid_file); /* xrdp.pid */

        if (fd == -1)
        {
            g_writeln("running in daemon mode with no access to pid files, quitting");
            g_deinit();
            g_exit(0);
        }

        if (g_file_write(fd, "0", 1) == -1)
        {
            g_writeln("running in daemon mode with no access to pid files, quitting");
            g_deinit();
            g_exit(0);
        }

        g_file_close(fd);
        g_file_delete(pid_file);
    }

    if (!no_daemon)
    {
        /* start of daemonizing code */
        pid = g_fork();

        if (pid == -1)
        {
            g_writeln("problem forking");
            g_deinit();
            g_exit(1);
        }

        if (0 != pid)
        {
            g_writeln("process %d started ok", pid);
            /* exit, this is the main process */
            g_deinit();
            g_exit(0);
        }

        g_sleep(1000);
        /* write the pid to file */
        pid = g_getpid();
        fd = g_file_open(pid_file); /* xrdp.pid */

        if (fd == -1)
        {
            g_writeln("trying to write process id to xrdp.pid");
            g_writeln("problem opening xrdp.pid");
            g_writeln("maybe no rights");
        }
        else
        {
            g_sprintf(text, "%d", pid);
            g_file_write(fd, text, g_strlen(text));
            g_file_close(fd);
        }

        g_sleep(1000);
        g_file_close(0);
        g_file_close(1);
        g_file_close(2);
        g_file_open("/dev/null");
        g_file_open("/dev/null");
        g_file_open("/dev/null");
        /* end of daemonizing code */
    }

    g_threadid = tc_get_threadid();
    g_listen = xrdp_listen_create();
    g_signal_user_interrupt(xrdp_shutdown); /* SIGINT */
    g_signal_kill(xrdp_shutdown); /* SIGKILL */
    g_signal_pipe(pipe_sig); /* SIGPIPE */
    g_signal_terminate(xrdp_shutdown); /* SIGTERM */
    g_signal_child_stop(xrdp_child); /* SIGCHLD */
    g_sync_mutex = tc_mutex_create();
    g_sync1_mutex = tc_mutex_create();
    pid = g_getpid();
    g_snprintf(text, 255, "xrdp_%8.8x_main_term", pid);
    g_term_event = g_create_wait_obj(text);

    if (g_term_event == 0)
    {
        g_writeln("error creating g_term_event");
    }

    g_snprintf(text, 255, "xrdp_%8.8x_main_sync", pid);
    g_sync_event = g_create_wait_obj(text);

    if (g_sync_event == 0)
    {
        g_writeln("error creating g_sync_event");
    }

    g_listen->startup_params = startup_params;
    xrdp_listen_main_loop(g_listen);
    xrdp_listen_delete(g_listen);
    tc_mutex_delete(g_sync_mutex);
    tc_mutex_delete(g_sync1_mutex);
    g_delete_wait_obj(g_term_event);
    g_delete_wait_obj(g_sync_event);

    /* only main process should delete pid file */
    if ((!no_daemon) && (pid == g_getpid()))
    {
        /* delete the xrdp.pid file */
        g_file_delete(pid_file);
    }

    g_free(startup_params);
    g_deinit();
    return 0;
}
