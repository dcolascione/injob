/**
 * injob: runs a program (Win32 or Cygwin) in a job object, imbuing it
 * and all its sub-processes with Cygwin job control support.
 *
 */

#define _WIN32_WINNT 0x0500 /*Win2k*/
#define STRICT
#define UNICODE 1
#define _UNICODE 1

#include <wchar.h>
#include <stdio.h>
#include <windows.h>
#include <ddk/ntapi.h>
#include <getopt.h>
#include <sys/cygwin.h>
#include <sys/queue.h>
#include <process.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/fcntl.h>
#include <errno.h>
#include <Tlhelp32.h>
#include <pthread.h>
#include <assert.h>

#define PRGNAME "injob"
#define PRGVER "1.4"
#define PRGAUTHOR "Daniel Colascione <dan.colascione@gmail.com>"
#define PRGCOPY "Copyright (C) 2011 " PRGAUTHOR
#define PRGLICENSE "GPLv2 or later <http://www.gnu.org/licenses/gpl-2.0.html>"

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

/* Gets set to PROCESS_QUERY_LIMITED_INFORMATION if we're running on
 * >= Vista.  Always better to use least privilege. */
static DWORD open_process_scan_flags = PROCESS_QUERY_INFORMATION;

/**
 * Small utility to run an arbitrary set of processes within a job
 * object.  We reach to Cygwin job control signals by appropriately
 * manipulating the job object, providing a crude form of job control
 * for Win32 applications being run from Cygwin programs.
 *
 * It works like this:
 *
 *   - Startup.
 *
 *   - Create a pipe with ends P_R and P_W.
 *
 *   - Block signals.
 *
 *   - Fork
 *
 *     * Child closes P_W, blocks reading P_R.  If it gets EOF, child
 *       knows parent died for some reason and exits without doing
 *       anything else.
 *
 *     * Child reads 1 byte from pipe, indicating all-clear.
 *
 *     * Child execs target program.
 *
 *   - Meanwhile parent closes P_R and knows child is blocked on pipe.
 *
 *   - Parent creates job object and puts the child
 *     into it (child is still blocked).
 *
 *   - Parent gives all-clear signal to child by writing one byte to
 *     P_W and closing it.
 *
 *   - Parent waits for SIGINT, SIGTERM, SIGCHLD, etc.
 *
 */

static BOOL WINAPI
(*XIsProcessInJob)(
    HANDLE ProcessHandle,
    HANDLE JobHandle,
    PBOOL Result
    );

#define CHK(op)                                         \
    ({                                                  \
        int chk_ret;                                    \
                                                        \
        do {                                            \
            chk_ret = (op);                             \
        } while (chk_ret == -1 && errno == EINTR);      \
                                                        \
        if (chk_ret == -1) {                            \
            fprintf (stderr, PRGNAME ": " #op ": %s\n", \
                     strerror (errno));                 \
            goto out;                                   \
        }                                               \
        chk_ret;                                        \
    })

#define CHK_W32_HANDLE(op)                              \
    ({                                                  \
        HANDLE chk_ret = (op);                          \
        if (chk_ret == NULL ||                          \
            chk_ret == INVALID_HANDLE_VALUE)            \
        {                                               \
            fprintf (stderr, PRGNAME ": " #op ": %s\n", \
                     errmsg (GetLastError ()));         \
            goto out;                                   \
        }                                               \
                                                        \
        chk_ret;                                        \
    })

#define CHK_W32_BOOL(op)                                \
    ({                                                  \
        BOOL chk_ret = (op);                            \
        if (chk_ret == FALSE) {                         \
            fprintf (stderr, PRGNAME ": " #op ": %s\n", \
                     errmsg (GetLastError ()));         \
            goto out;                                   \
        }                                               \
                                                        \
        chk_ret;                                        \
    })


#define PIPE_READ  0
#define PIPE_WRITE 1

struct suspend
{
    DWORD   thread_id;
    HANDLE  thread;

    SLIST_ENTRY (suspend) entries;
};

static void
usage()
{
    fprintf (
        stdout,
        PRGNAME " [OPTIONS] PROGRAM ARG1 ARG2...: Run PROGRAM in a job object\n"
        "\n"
        "  PROGRAM will be run in a job object.  A SIGHUP, SIGTERM, or SIGINT\n"
        "  sent to this proess will terminate PROGRAM and all its children.\n"
        "\n"
        "  By default, we kill all processes in the job and exit when PROGRAM\n"
        "  itself exits.  If --wait-all is passed, however, we delay exiting\n"
        "  until all processes in the job exit.\n"
        "\n"
        PRGNAME " -h\n"
        PRGNAME " --help\n"
        "\n"
        "  Display this help message.\n"
        "\n"
        PRGNAME " -a\n"
        PRGNAME " --wait-all\n"
        "\n"
        "  Wait for all processes in the job to exit before exiting instead of\n"
        "  exiting (and killing the job) after PROGRAM itself exits.\n"
        "\n"
        PRGNAME " -v\n"
        PRGNAME " --verbose\n"
        "\n"
        "  Trace process creation and destruction on stderr.\n"
        "\n"
        PRGNAME " -V\n"
        PRGNAME " --version\n"
        "\n"
        "  Display version information.\n"
	);
}

static void
versinfo ()
{
    fprintf (stdout,
             PRGNAME " " PRGVER "\n"
             PRGCOPY "\n"
             PRGLICENSE "\n"
        );
}

/* Convert a wide-character string to a malloced multibyte string
   encoded as specified in the current locale.  Return NULL on
   failure. */
static char*
to_mbs(const wchar_t* wcs)
{
    size_t mbs_length = wcstombs(NULL, wcs, 0) + 1;
    char* mbs = malloc(mbs_length * sizeof(*mbs));
    if(mbs != NULL) {
        if(wcstombs(mbs, wcs, mbs_length) == (size_t) -1) {
            free(mbs);
            mbs = NULL;
        }
    }

    return mbs;
}

/* Decode a Win32 error code to a localized string encoded according
   to the current locale.  Return a malloc()ed string. */
static char*
errmsg(DWORD errorcode)
{
    wchar_t* wcsmsg = NULL;
    char* msg = NULL;

    FormatMessageW(
        (FORMAT_MESSAGE_FROM_SYSTEM|
         FORMAT_MESSAGE_ALLOCATE_BUFFER),
        NULL,
        errorcode,
        0,
        (LPWSTR)&wcsmsg,
        0,
        NULL);

    if(wcsmsg != NULL) {
        msg = to_mbs(wcsmsg);
        LocalFree(wcsmsg);
        if(msg && msg[0] && msg[strlen(msg) - 1] == '\n') {
            msg[strlen(msg) - 1] = '\0';
        }
    }

    if(msg == NULL) {
        msg = strdup("[unknown error]");
    }

    return msg;
}

/* Holds a list of processes we've suspended. */

typedef SLIST_HEAD (suspend_list_head, suspend) suspend_list_head_t;
                                                static suspend_list_head_t suspend_list_head =
    SLIST_HEAD_INITIALIZER (suspend_list_head);

                                                /* Resume everything we remember we suspended. */
                                                static void
                                                resume_all ()
{
    struct suspend* susp;

    while (!SLIST_EMPTY (&suspend_list_head)) {
        susp = SLIST_FIRST (&suspend_list_head);
        SLIST_REMOVE_HEAD (&suspend_list_head, entries);

        /* Don't care about failures here. Best effort. */
        ResumeThread (susp->thread);
        CloseHandle (susp->thread);
        free (susp);
    }
}

static BOOL
is_thread_already_suspended (DWORD thread_id)
{
    struct suspend* s;
    SLIST_FOREACH (s, &suspend_list_head, entries) {
        if (s->thread_id == thread_id) {
            return TRUE;
        }
    }

    return FALSE;
}

/* Brute force. Loop through all proceses in the system and suspend
 * threads in our job until we're out of threads to suspend. */
static void
suspend_all_in_job (HANDLE job)
{
    unsigned nr_suspended;
    HANDLE snap;
    THREADENTRY32 thent;
    HANDLE proc;
    HANDLE thread;
    BOOL process_in_job;
    struct suspend* new_susp = NULL;
    unsigned try_count = 1000;

    do {
        nr_suspended = 0;
        snap = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, 0);

        if (snap == NULL) {
            goto next_snapshot;
        }

        memset (&thent, 0, sizeof (thent));
        thent.dwSize = sizeof (thent);

        if (Thread32First (snap, &thent) == FALSE) {
            goto next_snapshot;
        }

        do {
            /* Thread32{First,Next} is allowed to return a struct
               smaller that the one we asked for, so make sure the
               fields we used are included in this structure. */
            if (thent.dwSize < sizeof (DWORD)*4) {
                goto next_thread;
            }

            proc = NULL;
            thread = NULL;

            proc = OpenProcess (open_process_scan_flags,
                                FALSE /*do not inherit*/,
                                thent.th32OwnerProcessID);

            if (proc == NULL) {
                goto next_thread;
            }

            if (XIsProcessInJob (proc, job, &process_in_job) == FALSE) {
                goto next_thread;
            }

            if (process_in_job == FALSE) {
                goto next_thread;
            }

            /* We found a thread in a process that's in our job.  Now
             * this part is O(N^2): we examine our entire list
             * so far to make sure we haven't already noticed this
             * thread. */

            if (is_thread_already_suspended (thent.th32ThreadID)) {
                goto next_thread;
            }

            thread = OpenThread (THREAD_SUSPEND_RESUME,
                                 FALSE /*do not inherit*/,
                                 thent.th32ThreadID);

            if (thread == NULL) {
                goto next_thread;
            }

            /* We found a match we didn't notice before. */

            new_susp = malloc (sizeof (*new_susp));
            if (new_susp == NULL) {
                goto next_thread;
            }

            new_susp->thread = thread;
            new_susp->thread_id = thent.th32ThreadID;

            /* Try to suspend the thread */

            if (SuspendThread (thread) == (DWORD)-1) {
                goto next_thread;
            }

            SLIST_INSERT_HEAD (&suspend_list_head, new_susp, entries);
            ++nr_suspended;

            thread = NULL;
            new_susp = NULL;

            next_thread:

            free (new_susp);

            if (thread != NULL) {
                CloseHandle (thread);
            }

            if (proc != NULL) {
                CloseHandle (proc);
            }

            memset (&thent, 0, sizeof (thent));
            thent.dwSize = sizeof (thent);
        } while (Thread32Next (snap, &thent));

        next_snapshot:
        if (snap != NULL) {
            CloseHandle (snap);
            snap = NULL;
        }
    } while (--try_count && nr_suspended > 0);
}

static void
print_all_in_job (HANDLE job)
{
    HANDLE snap;
    PROCESSENTRY32 procent;
    HANDLE proc;
    BOOL process_in_job;
    int procinjob=0;

    snap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);

    if (snap == NULL) {
        return;
    }

    fprintf (stderr, "Processes in job:\n");

    memset (&procent, 0, sizeof (procent));
    procent.dwSize = sizeof (procent);

    if (Process32First (snap, &procent) == FALSE) {
        CloseHandle (snap);
        return;
    }

    do {
        /* Process32{First,Next} is allowed to return a struct
           smaller that the one we asked for, so make sure the
           fields we used are included in this structure. */
        if (procent.dwSize < sizeof (DWORD)*4) {
            goto next_process;
        }

        proc = OpenProcess (open_process_scan_flags,
                            FALSE /*do not inherit*/,
                            procent.th32ProcessID);

        if (proc == NULL) {
            goto next_process;
        }

        if (XIsProcessInJob (proc, job, &process_in_job) == FALSE) {
            goto next_process;
        }

        if (process_in_job == FALSE) {
            goto next_process;
        }

        fprintf (stderr, "  %u\n", (unsigned)procent.th32ProcessID);
        ++procinjob;

      next_process:

        if (proc != NULL) {
            CloseHandle (proc);
        }

        memset (&procent, 0, sizeof (procent));
        procent.dwSize = sizeof (procent);
    } while (Process32Next (snap, &procent));

    if (snap != NULL) {
        CloseHandle (snap);
    }

    fprintf (stderr, "End process list: found %d\n", procinjob);
}


static void
dummy_sighandler (int dummy)
{}

static int
child_main (int argc, char** argv, int* child_pipe)
{
    int ret = 1;
    ssize_t rret;
    char buf[1];
    int child_status;
    int ctty;

    CHK (close (child_pipe[PIPE_WRITE]));

    /* Start a new session so our children don't receive tty and shell
       control signals. We handle job control for our children by
       ourselves. */
    CHK (setsid ());

    do {
        rret = read (child_pipe[PIPE_READ], &buf, 1);
    } while (rret == -1 && errno == EINTR);

    if (rret == 0) {
        /* Parent died before it readied us, so die along with it. */
        goto out;
    }

    CHK (close (child_pipe[PIPE_READ]));

    do {
        ret = execvp (argv[0], argv);
    } while (ret == -1 && errno == EINTR);

    fprintf (stderr, PRGNAME ": could not spawn \"%s\": %s\n",
             argv[0], strerror (errno));
    ret = 128;

    out:
    return ret;
}

static HANDLE completion_port;
static pthread_t main_thread;
static int verbose_mon = 0;

// Copied from MSDN and renamed to avoid conflict with future Cygwin
// _PEB definition.
typedef struct _XPEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PVOID                         Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  BYTE                          Reserved4[104];
  PVOID                         Reserved5[52];
  PVOID                         PostProcessInitRoutine;
  BYTE                          Reserved6[128];
  PVOID                         Reserved7[1];
  ULONG                         SessionId;
} XPEB, *PXPEB;

#define _countof(array)                         \
    ( sizeof (array) / sizeof (*array) )

static wchar_t*
get_process_command_line (DWORD pid)
{
    HANDLE process = NULL;
    wchar_t* cmdline = NULL;
    wchar_t* cmdline_tmp = NULL;
    NTSTATUS nt;
    PROCESS_BASIC_INFORMATION basicinfo;
    XPEB peb;
    SIZE_T bytes_copied;
    RTL_USER_PROCESS_PARAMETERS pparams;
    wchar_t buf[256];

    process = OpenProcess (PROCESS_ALL_ACCESS,
                           FALSE, pid);

    if (!process) {
        swprintf (buf, _countof (buf), L"[[OpenProcess FAILED: %u]]",
                  (unsigned) GetLastError ());
        cmdline = wcsdup (buf);
        goto out;
    }

    nt = NtQueryInformationProcess (process,
                                    ProcessBasicInformation,
                                    &basicinfo,
                                    sizeof (basicinfo),
                                    NULL);
    if (!NT_SUCCESS (nt)) {
        swprintf (buf, _countof (buf),
                  L"[[NtQueryInformationProcess FAILED: %u]]",
                  (unsigned) nt);
        cmdline = wcsdup (buf);
        goto out;
    }

    if (!ReadProcessMemory (
            process,
            &(((PXPEB)(basicinfo.PebBaseAddress))->ProcessParameters),
            &peb.ProcessParameters,
            sizeof (peb.ProcessParameters),
            &bytes_copied))
    {
        swprintf (buf, _countof (buf),
                  L"[[ReadProcessMemory[peb] FAILED: %u]]",
                  (unsigned) GetLastError ());
        cmdline = wcsdup (buf);
        goto out;
    }

    if (!ReadProcessMemory (process,
                            &peb.ProcessParameters->CommandLine,
                            &pparams.CommandLine,
                            sizeof (pparams.CommandLine),
                            &bytes_copied))
    {
        swprintf (buf, _countof (buf),
                  L"[[ReadProcessMemory[pparams] FAILED: %u]]",
                  (unsigned) GetLastError ());
        cmdline = wcsdup (buf);
        goto out;
    }

    cmdline_tmp = malloc (pparams.CommandLine.Length + sizeof (wchar_t));
    if (!ReadProcessMemory (process, pparams.CommandLine.Buffer,
                            cmdline_tmp, pparams.CommandLine.Length,
                            &bytes_copied))
    {
        swprintf (buf, _countof (buf),
                  L"[[ReadProcessMemory[cmdline] FAILED: %u]]",
                  (unsigned) GetLastError ());
        cmdline = wcsdup (buf);
        goto out;
    }

    cmdline = cmdline_tmp;
    cmdline_tmp = NULL;
    cmdline[pparams.CommandLine.Length / sizeof (wchar_t)] = L'\0';

  out:

    if (process) {
        CloseHandle (process);
    }

    free (cmdline_tmp);

    return cmdline;
}

/* Wait for our job object to empty. */
static void*
do_monitor_thread (void* ignored)
{
    DWORD msg;
    ULONG_PTR key;
    OVERLAPPED* overlapped;

  get_next_message:

    CHK_W32_BOOL (
        GetQueuedCompletionStatus (completion_port,
                                   &msg, &key, &overlapped,
                                   INFINITE));
    switch(msg) {
        case JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO:
            goto out;

        case JOB_OBJECT_MSG_NEW_PROCESS: {
            if (verbose_mon) {
                DWORD pid = (DWORD) overlapped;
                wchar_t* cmdline = get_process_command_line (pid);
                fprintf (stderr, "new process: %u: %S\n",
                         (unsigned) pid, cmdline);
                free (cmdline);
            }

            goto get_next_message;
        }

        case JOB_OBJECT_MSG_EXIT_PROCESS:
            if (verbose_mon) {
                fprintf (stderr, "process exited: %u\n",
                         (unsigned) overlapped);
            }

            goto get_next_message;

        default:
            goto get_next_message;
    }

    out:
    if (verbose_mon) {
        fprintf (stderr, "job empty\n");
    }

    pthread_kill (main_thread, SIGUSR1);
    sleep (10);
    assert (!"should have exited by now");
    exit (4);
    return NULL;
}

int
main (int argc, char** argv)
{
    int c;
    int ret = 1;
    HANDLE job;
    int child_status;
    sigset_t waitmask;
    sigset_t origmask;
    pid_t child_pid;
    int child_pipe[2];
    int sig;
    DWORD child_w32_pid;
    HANDLE child_proc_handle;
    HANDLE kernel32dll;
    OSVERSIONINFO version_info;
    pthread_t monitor_thread;
    int exit_after_sigchld = 1;

    static const struct option
        longopts[] =
        {
            /* Name           has_arg  flag  val */
            { "help",         0,       0,    'h' },
            { "version",      0,       0,    'V' },
            { "verbose",      0,       0,    'v' },
            { "wait-all",     0,       0,    'a' },
            { 0 }
        };

    while ((c = getopt_long (argc, argv, "+Vhlva", longopts, 0)) != -1) {
        switch (c) {
            case 'h':
                usage ();
                ret  = 0;
                goto out;
            case 'V':
                versinfo ();
                ret = 0;
                goto out;
            case 'v':
                verbose_mon = 1;
                break;
            case 'a':
                exit_after_sigchld = 0;
                break;
            default:
                fprintf (stderr, PRGNAME ": use --help for usage\n");
                goto out;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc == 0) {
        fprintf (stderr, PRGNAME ": missing PROGRAM argument\n");
        fprintf (stderr, PRGNAME ": use --help for usage\n");
        goto out;
    }

    kernel32dll = CHK_W32_HANDLE (LoadLibrary (L"kernel32.dll"));
    XIsProcessInJob = GetProcAddress (kernel32dll, "IsProcessInJob");
    if (XIsProcessInJob == NULL) {
        fprintf (stderr, PRGNAME ": could not find IsProcessInJob: OS too old?\n");
        goto out;
    }

    version_info.dwOSVersionInfoSize = sizeof (version_info);
    CHK_W32_BOOL (GetVersionEx (&version_info));

    /* Vista or higher lets us use more limited permissions opening
     * process objects. */
    if (version_info.dwMajorVersion >= 6) {
        open_process_scan_flags = PROCESS_QUERY_LIMITED_INFORMATION;
    }

    CHK (pipe (child_pipe));
    fflush (NULL);

    /* Signals blocked below, except while waiting. */

    CHK (sigemptyset (&waitmask));
    CHK (sigaddset (&waitmask, SIGCHLD));
    CHK (sigaddset (&waitmask, SIGHUP));
    CHK (sigaddset (&waitmask, SIGUSR1));
    CHK (sigaddset (&waitmask, SIGUSR2));
    CHK (sigaddset (&waitmask, SIGTERM));
    CHK (sigaddset (&waitmask, SIGINT));
    CHK (sigaddset (&waitmask, SIGTSTP));
    CHK (sigprocmask (SIG_BLOCK, &waitmask, &origmask));

    signal (SIGCHLD, dummy_sighandler);
    signal (SIGTERM, dummy_sighandler);
    signal (SIGINT,  dummy_sighandler);
    signal (SIGTSTP, dummy_sighandler);
    signal (SIGUSR1, dummy_sighandler);
    signal (SIGUSR2, dummy_sighandler);

    /* Create child.  Child will just wait for us at first. */

    child_pid = CHK (fork ());
    if (child_pid == 0) {
        CHK (sigprocmask (SIG_SETMASK, &origmask, NULL));
        return child_main (argc, argv, child_pipe);
    }

    CHK (close (child_pipe[PIPE_READ]));

    /* Child is alive and blocked. Set up its job object. */

    child_w32_pid = (DWORD)cygwin_internal (
        CW_CYGWIN_PID_TO_WINPID, child_pid);

    if (child_w32_pid == 0) {
        fprintf (stderr, PRGNAME ": could not get child W32 PID\n");
        goto out;
    }

    child_proc_handle = CHK_W32_HANDLE (
        OpenProcess (PROCESS_ALL_ACCESS,
                     FALSE,
                     child_w32_pid));

    job = CHK_W32_HANDLE (CreateJobObject (NULL, NULL));

    /* Associate our new job object with a completion port so we get a
     * message when all processes in the job exit. */
    completion_port = CHK_W32_HANDLE (
        CreateIoCompletionPort (INVALID_HANDLE_VALUE, NULL, 0, 0));

    {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT assoc = { 0, completion_port };
        CHK_W32_BOOL (SetInformationJobObject(
                          job, JobObjectAssociateCompletionPortInformation,
                          &assoc, sizeof (assoc)));
    }

    /* Actually add the child to the job object. */
    CHK_W32_BOOL (AssignProcessToJobObject (job, child_proc_handle));
    CHK_W32_BOOL (CloseHandle (child_proc_handle));

    /* Send ourselves a SIGUSR1 when the job becomes empty.  Only
     * necessary if we want to stick around after SIGCHLD. */
    if (!exit_after_sigchld)  {
        main_thread = pthread_self ();
        CHK (pthread_create (&monitor_thread, NULL, do_monitor_thread, NULL));
    }

    /* Child is now in the job object. Send the all-clear signal,
     * causing the child to exec the program we actually want to
     * run. */
    CHK (write (child_pipe[PIPE_WRITE], &ret /* arbitary byte */, 1));
    CHK (close (child_pipe[PIPE_WRITE]));

    /* Begin processing signals as they come in. */

    get_another_signal:

    switch ((sig = sigwaitinfo (&waitmask, NULL))) {
        case SIGCHLD:
            if (verbose_mon) {
                fprintf (stderr, "SIGCHLD\n");
            }

            if (exit_after_sigchld) {
                TerminateJobObject (job, 0);
                goto done;
            }

            goto get_another_signal;
        default:
            fprintf (stderr, PRGNAME ": unexpected signal %d: %s\n",
                     sig, strerror (errno));
            /* Fall through */
        case SIGHUP:
        case SIGTERM:
        case SIGINT:
            /* We were asked to quit.  Kill everything in the job. */
            CHK_W32_BOOL (TerminateJobObject (job, 128 + sig));
            child_pid = 0; /* Don't use waitpid; just return the
                              signal + 128, like a shell. */
            goto done;
        case SIGUSR1:
            goto done;
        case SIGUSR2:
            print_all_in_job (job);
            goto get_another_signal;
        case SIGTSTP:
            suspend_all_in_job (job);
            raise (SIGSTOP); /* Block until somebody resumes us. */
            resume_all ();
            goto get_another_signal;
    }

    done:

    if (child_pid > 0) {
        CHK (wait (&child_status));

        ret = ( WIFEXITED (child_status)
                ? WEXITSTATUS (child_status)
                : 128 + WTERMSIG (child_status) );
    } else {
        ret = 128 + sig;
    }

    out:
    return ret;
}
