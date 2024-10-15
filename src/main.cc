/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "main.h"

#include <limits.h>
#include <linux/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <chrono>

#include <sstream>
#include <unordered_map>

#include "CRIU.h"
#include "Command.h"
#include "Flags.h"
#include "RecordCommand.h"
#include "ReplayCommand.h"
#include "core.h"
#include "log.h"
#include "util.h"

#if XDEBUG_PATCHING
#include <algorithm>
#endif

using namespace std;

namespace rr {

int step_counter = 0;
#if XDEBUG_LATENCY
// Used in calc latency added by RR record
std::chrono::time_point<std::chrono::steady_clock> RR_start;
std::chrono::time_point<std::chrono::steady_clock> before_ptrace_seize;
std::chrono::time_point<std::chrono::steady_clock> tracee_execve;
std::chrono::time_point<std::chrono::steady_clock> start_new_compressed_writer;
std::chrono::time_point<std::chrono::steady_clock> end_new_compressed_writer;
std::chrono::time_point<std::chrono::steady_clock> tracee_exit;
std::chrono::time_point<std::chrono::steady_clock> RR_exit;
std::chrono::time_point<std::chrono::steady_clock> after_wait;
std::chrono::time_point<std::chrono::steady_clock> before_resume;
std::chrono::time_point<std::chrono::steady_clock> before_record;
std::chrono::time_point<std::chrono::steady_clock> RR_after_record;
std::chrono::time_point<std::chrono::steady_clock> overall_after_wait;
std::chrono::time_point<std::chrono::steady_clock> overall_before_resume;
std::vector<double> overall_block_times;
bool overall_stopped_after_wait;

bool after_tracee_exit = false;

bool no_execve = true;
std::vector<double> schedule_wait_times;
std::vector<double> no_execve_wait_times;
std::vector<double> no_execve_blocking_times;
std::vector<double> no_execve_record_step_times;

std::vector<double> block_times;
bool stopped_after_wait = false;

std::chrono::time_point<std::chrono::steady_clock> before_criu_checkpoint;
std::chrono::time_point<std::chrono::steady_clock> after_criu_checkpoint;
bool is_checkpointed = false;
std::chrono::time_point<std::chrono::steady_clock> before_criu_restore;
std::chrono::time_point<std::chrono::steady_clock> after_criu_restore;

std::chrono::time_point<std::chrono::steady_clock> step_start;
std::chrono::time_point<std::chrono::steady_clock> step_end;
double total_step_counter_time = 0.0;

std::chrono::time_point<std::chrono::steady_clock> schedule_start;
std::chrono::time_point<std::chrono::steady_clock> schedule_end;
std::chrono::time_point<std::chrono::steady_clock> schedule_allow_switch_start;
std::chrono::time_point<std::chrono::steady_clock> schedule_allow_switch_end;
double total_schedule_time = 0.0;
double total_schedule_allow_switch_time = 0.0;

std::chrono::time_point<std::chrono::steady_clock> rec_prepare_syscall_start;
std::chrono::time_point<std::chrono::steady_clock> rec_prepare_syscall_end;
double total_rec_prepare_syscall_time = 0.0;

std::chrono::time_point<std::chrono::steady_clock> rec_process_syscall_start;
std::chrono::time_point<std::chrono::steady_clock> rec_process_syscall_end;
double total_rec_process_syscall_time = 0.0;

std::chrono::time_point<std::chrono::steady_clock> record_event_start;
std::chrono::time_point<std::chrono::steady_clock> record_event_end;
double total_record_event_time = 0.0;

std::chrono::time_point<std::chrono::steady_clock> ptrace_event_seccomp_start;
std::chrono::time_point<std::chrono::steady_clock> ptrace_event_seccomp_end;
double total_ptrace_event_seccomp_time = 0.0;

std::chrono::time_point<std::chrono::steady_clock> handle_signal_start;
std::chrono::time_point<std::chrono::steady_clock> handle_signal_end;
double total_handle_signal_time = 0.0;

std::chrono::time_point<std::chrono::steady_clock> did_waitpid_start;
std::chrono::time_point<std::chrono::steady_clock> did_waitpid_end;
double total_did_waitpid_time = 0.0;

double total_patching_time = 0.0;

#if XDEBUG_WAIT
int wait1_counter = 0;
int wait2_counter = 0;
int wait3_counter = 0;
int wait4_counter = 0;
int try_wait_counter = 0;
int waitpid1_counter = 0;
int waitpid2_counter = 0;

int overall_wait_counter = 0;
#endif
#if XDEBUG_RESUME
int task_continue_counter = 0;
int resume1 = 0;
int resume2 = 0;
int resume3 = 0;
int resume4 = 0;
int resume5 = 0;

int overall_resume_counter = 0;
#endif
#endif

#if XDEBUG_PATCHING
std::vector<string> patching_names;

std::unordered_map<intptr_t, std::vector<double>> before_patching;

std::chrono::time_point<std::chrono::steady_clock> start_syscall;
std::chrono::time_point<std::chrono::steady_clock> end_syscall;

std::chrono::time_point<std::chrono::steady_clock> after_patch_end_syscall;

int start_syscallno = -1;

bool exiting_syscall = false;
#endif

#if CHECKPOINT
pid_t tracee_pid = -1;
#endif

// Show version and quit.
static bool show_version = false;
static bool show_cmd_list = false;

void assert_prerequisites(bool use_syscall_buffer) {
  struct utsname uname_buf;
  memset(&uname_buf, 0, sizeof(uname_buf));
  if (!uname(&uname_buf)) {
    unsigned int major, minor;
    char dot;
    stringstream stream(uname_buf.release);
    stream >> major >> dot >> minor;
    if (KERNEL_VERSION(major, minor, 0) < KERNEL_VERSION(3, 4, 0)) {
      FATAL() << "Kernel doesn't support necessary ptrace "
              << "functionality; need 3.4.0 or better.";
    }

    if (use_syscall_buffer &&
        KERNEL_VERSION(major, minor, 0) < KERNEL_VERSION(3, 5, 0)) {
      FATAL() << "Your kernel does not support syscall "
              << "filtering; please use the -n option";
    }
  }
}

void print_version(FILE* out) { fprintf(out, "rr version %s\n", RR_VERSION); }

void print_global_options(FILE* out) {
  fputs(
      "Global options:\n"
      "  --disable-cpuid-faulting   disable use of CPUID faulting\n"
      "  --disable-ptrace-exit_events disable use of PTRACE_EVENT_EXIT\n"
      "  --resource-path=PATH       specify the paths that rr should use to "
      "find\n"
      "                             files such as rr_page_*.  These files "
      "should\n"
      "                             be located in PATH/bin, PATH/lib[64], and\n"
      "                             PATH/share as appropriate.\n"
      "  -A, --microarch=<NAME>     force rr to assume it's running on a CPU\n"
      "                             with microarch NAME even if runtime "
      "detection\n"
      "                             says otherwise.  NAME should be a string "
      "like\n"
      "                             'Ivy Bridge'. Note that rr will not work "
      "with\n"
      "                             Intel Merom or Penryn microarchitectures.\n"
      "  -F, --force-things         force rr to do some things that don't "
      "seem\n"
      "                             like good ideas, for example launching an\n"
      "                             interactive emergency debugger if stderr\n"
      "                             isn't a tty.\n"
      "  -E, --fatal-errors         any warning or error that is printed is\n"
      "                             treated as fatal\n"
      "  -M, --mark-stdio           mark stdio writes with [rr <PID> <EV>]\n"
      "                             where EV is the global trace time at\n"
      "                             which the write occurs and PID is the pid\n"
      "                             of the process it occurs in.\n"
      "  -N, --version              print the version number and exit\n"
      "  -S, --suppress-environment-warnings\n"
      "                             suppress warnings about issues in the\n"
      "                             environment that rr has no control over\n"
      "  --log=<spec>               Set logging config to <spec>. See RR_LOG.\n"
      "\n"
      "Environment variables:\n"
      " $RR_LOG        logging configuration ; e.g. RR_LOG=all:warn,Task:debug\n"
      " $RR_TMPDIR     to use a different TMPDIR than the recorded program\n"
      " $_RR_TRACE_DIR where traces will be stored;\n"
      "                falls back to $XDG_DATA_HOME / $HOME/.local/share/rr\n",
      out);
}

void list_commands(FILE* out) {
  Command::print_help_all(out);
}

void print_usage(FILE* out) {
  print_version(out);
  fputs("\nUsage:\n", out);
  list_commands(out);
  fputs("\nIf no subcommand is provided, we check if the first non-option\n"
        "argument is a directory. If it is, we assume the 'replay' subcommand\n"
        "otherwise we assume the 'record' subcommand.\n\n",
        out);
  print_global_options(out);

  /* we should print usage when utility being wrongly used.
     use 'exit' with failure code */
  exit(EXIT_FAILURE);
}

static void init_random() {
  // Not very good, but good enough for our non-security-sensitive needs.
  int key;
  good_random(&key, sizeof(key));
  srandom(key);
  srand(key);
}

bool parse_global_option(std::vector<std::string>& args) {
  static const OptionSpec options[] = {
    { 0, "disable-cpuid-faulting", NO_PARAMETER },
    { 1, "disable-ptrace-exit-events", NO_PARAMETER },
    { 2, "resource-path", HAS_PARAMETER },
    { 3, "log", HAS_PARAMETER },
    { 4, "non-interactive", NO_PARAMETER },
    { 'A', "microarch", HAS_PARAMETER },
    { 'C', "checksum", HAS_PARAMETER },
    { 'D', "dump-on", HAS_PARAMETER },
    { 'E', "fatal-errors", NO_PARAMETER },
    { 'F', "force-things", NO_PARAMETER },
    { 'K', "check-cached-mmaps", NO_PARAMETER },
    { 'L', "list-commands", NO_PARAMETER },
    { 'M', "mark-stdio", NO_PARAMETER },
    { 'N', "version", NO_PARAMETER },
    { 'S', "suppress-environment-warnings", NO_PARAMETER },
    { 'T', "dump-at", HAS_PARAMETER },
  };

  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  Flags& flags = Flags::get_for_init();
  switch (opt.short_name) {
    case 0:
      flags.disable_cpuid_faulting = true;
      break;
    case 1:
      flags.disable_ptrace_exit_events = true;
      break;
    case 2:
      flags.resource_path = opt.value;
      if (flags.resource_path.back() != '/') {
        flags.resource_path.append("/");
      }
      break;
    case 3:
      apply_log_spec(opt.value.c_str());
      break;
    case 4:
      flags.non_interactive = true;
      break;
    case 'A':
      flags.forced_uarch = opt.value;
      break;
    case 'C':
      if (opt.value == "on-syscalls") {
        LOG(info) << "checksumming on syscall exit";
        flags.checksum = Flags::CHECKSUM_SYSCALL;
      } else if (opt.value == "on-all-events") {
        LOG(info) << "checksumming on all events";
        flags.checksum = Flags::CHECKSUM_ALL;
      } else {
        flags.checksum = strtoll(opt.value.c_str(), NULL, 10);
        LOG(info) << "checksumming on at event " << flags.checksum;
      }
      break;
    case 'D':
      if (opt.value == "RDTSC") {
        flags.dump_on = Flags::DUMP_ON_RDTSC;
      } else {
        flags.dump_on = strtoll(opt.value.c_str(), NULL, 10);
      }
      break;
    case 'E':
      flags.fatal_errors_and_warnings = true;
      break;
    case 'F':
      flags.force_things = true;
      break;
    case 'K':
      flags.check_cached_mmaps = true;
      break;
    case 'M':
      flags.mark_stdio = true;
      break;
    case 'S':
      flags.suppress_environment_warnings = true;
      break;
    case 'T':
      flags.dump_at = strtoll(opt.value.c_str(), NULL, 10);
      break;
    case 'N':
      show_version = true;
      break;
    case 'L':
      show_cmd_list = true;
      break;
    default:
      DEBUG_ASSERT(0 && "Invalid flag");
  }
  return true;
}

static char* saved_argv0_;
static size_t saved_argv0_space_;

char* saved_argv0() {
  return saved_argv0_;
}
size_t saved_argv0_space() {
  return saved_argv0_space_;
}

} // namespace rr

using namespace rr;

int main(int argc, char* argv[]) {

  std::chrono::time_point<std::chrono::steady_clock> origin_time = chrono::steady_clock::now();
  #if XDEBUG_LATENCY
    RR_start = chrono::steady_clock::now();
    LOG(debug) << "RR_start: " << chrono::duration <double, milli> (RR_start - origin_time).count() << " ms";
    cout << "RR_start: " << chrono::duration <double, milli> (RR_start - origin_time).count() << " ms" << endl;
    pid_t pid = getpid();
    LOG(debug) << "RR PID:" << pid;
    cout << "RR PID:" << pid << std::endl;
  #endif
  rr::saved_argv0_ = argv[0];
  rr::saved_argv0_space_ = argv[argc - 1] + strlen(argv[argc - 1]) + 1 - rr::saved_argv0_;

  init_random();
  raise_resource_limits();
  vector<string> args;
  for (int i = 1; i < argc; ++i) {
    args.push_back(argv[i]);
  }

  while (parse_global_option(args)) {
  }

  if (show_version) {
    print_version(stdout);
    return 0;
  }
  if (show_cmd_list) {
    list_commands(stdout);
    return 0;
  }

  if (args.size() == 0) {
    print_usage(stderr);
  }

  auto command = Command::command_for_name(args[0]);
  if (command) {
    args.erase(args.begin());
  } else {
    if (!Command::verify_not_option(args)) {
      print_usage(stderr);
    }
    if (is_directory(args[0].c_str())) {
      command = ReplayCommand::get();
    } else {
      command = RecordCommand::get();
    }
  }
  int res = command->run(args);

  #if XDEBUG_LATENCY
    RR_exit = chrono::steady_clock::now();
    #if LATENCY_OUTPUT
    double total_blocking = 0;
    for (auto time : block_times) {
      total_blocking += time;
    }

    double total_no_execve_waiting = 0;
    for (auto time : schedule_wait_times) {
      total_no_execve_waiting += time;
    }

    double total_overall_blocking = 0;
    for (auto time : overall_block_times) {
      total_overall_blocking += time;
    }

    cout << "block count: " << block_times.size() << endl;
    cout << "total blocking time: " << total_blocking << " ms" << endl;
    cout << "avg blocking time: " << total_blocking / block_times.size() << " ms" << endl;
    cout << "total no execve waiting time: " << total_no_execve_waiting << " ms" << endl;
    cout << "total_overall_blocking time: " << total_overall_blocking << " ms" << endl;

    cout << "RR after record - RR exit: " << chrono::duration <double, milli> (RR_exit - RR_after_record).count() << " ms" << endl;
    cout << "tracee exit - RR exit: " << chrono::duration <double, milli> (RR_exit - tracee_exit).count() << " ms" << endl;
    cout << "RR start - RR exit: " << chrono::duration <double, milli> (RR_exit - RR_start).count() << " ms" << endl;
    cout << "step_counter: " << step_counter << endl;
    cout << "total_step_counter_time: " << total_step_counter_time << endl;
    cout << "total_schedule_time: " << total_schedule_time << endl;
    cout << "total_schedule_allow_switch_time: " << total_schedule_allow_switch_time << endl;
    cout << "total_rec_prepare_syscall_time: " << total_rec_prepare_syscall_time << endl;
    cout << "total_rec_process_syscall_time: " << total_rec_process_syscall_time << endl;
    cout << "total_record_event_time: " << total_record_event_time << endl;
    cout << "total_patching_time: " << total_patching_time << endl;
    cout << "total_ptrace_event_seccomp_time: " << total_ptrace_event_seccomp_time << endl;
    cout << "total_handle_signal_time: " << total_handle_signal_time << endl;
    cout << "total_did_waitpid_time: " << total_did_waitpid_time << endl;

    LOG(debug) << "block count: " << block_times.size();
    LOG(debug) << "total blocking time: " << total_blocking << " ms";
    LOG(debug) << "avg blocking time: " << total_blocking / block_times.size() << " ms";
    LOG(debug) << "total no execve waiting time: " << total_no_execve_waiting << " ms";
    LOG(debug) << "total_overall_blocking time: " << total_overall_blocking << " ms";

    LOG(debug) << "RR after record - RR exit: " << chrono::duration <double, milli> (RR_exit - RR_after_record).count() << " ms";
    LOG(debug) << "tracee exit - RR exit: " << chrono::duration <double, milli> (RR_exit - tracee_exit).count() << " ms";
    LOG(debug) << "RR start - RR exit: " << chrono::duration <double, milli> (RR_exit - RR_start).count() << " ms";
    LOG(debug) << "step_counter: " << step_counter;
    LOG(debug) << "total_step_counter_time: " << total_step_counter_time;
    LOG(debug) << "total_schedule_time: " << total_schedule_time;
    LOG(debug) << "total_schedule_allow_switch_time: " << total_schedule_allow_switch_time;
    LOG(debug) << "total_rec_prepare_syscall_time: " << total_rec_prepare_syscall_time;
    LOG(debug) << "total_rec_process_syscall_time: " << total_rec_process_syscall_time;
    LOG(debug) << "total_record_event_time: " << total_record_event_time;
    LOG(debug) << "total_patching_time: " << total_patching_time;
    LOG(debug) << "total_ptrace_event_seccomp_time: " << total_ptrace_event_seccomp_time;
    LOG(debug) << "total_handle_signal_time: " << total_handle_signal_time;
    LOG(debug) << "total_did_waitpid_time: " << total_did_waitpid_time;
    #endif
  #if XDEBUG_WAIT
    cout << "wait() call times distribution:" << endl;
    cout << "\twait 1: " << wait1_counter << endl;
    cout << "\twait 2: " << wait2_counter << endl;
    cout << "\twait 3: " << wait3_counter << endl;
    cout << "\twait 4: " << wait4_counter << endl;
    cout << "\ttry wait: " << try_wait_counter << endl;

    cout << "waitpid() call times distribution:" << endl;
    cout << "\twaitpid 1: " << waitpid1_counter << endl;
    cout << "\twaitpid 2: " << waitpid2_counter << endl;

    cout << "\toverall_wait_counter: " << overall_wait_counter << endl;

    LOG(debug) << "wait() call times distribution:";
    LOG(debug) << "\twait 1: " << wait1_counter;
    LOG(debug) << "\twait 2: " << wait2_counter;
    LOG(debug) << "\twait 3: " << wait3_counter;
    LOG(debug) << "\twait 4: " << wait4_counter;

    LOG(debug) << "waitpid() call times distribution:";
    LOG(debug) << "\twaitpid 1: " << waitpid1_counter;
    LOG(debug) << "\twaitpid 2: " << waitpid2_counter;

    LOG(debug) << "\toverall_wait_counter: " << overall_wait_counter;
  #endif

  #if XDEBUG_RESUME
    cout << "\ntask_continue: " << task_continue_counter << endl;
    cout << "resume_execution() call times distribution: " << endl;
    cout << "\tresume 1: " << resume1 << endl;
    cout << "\tresume 2: " << resume2 << endl;
    cout << "\tresume 3: " << resume3 << endl;
    cout << "\tresume 4: " << resume4 << endl;
    cout << "\tresume 5: " << resume5 << endl;
    cout << "\toverall_resume_counter: " << overall_resume_counter << endl;

    LOG(debug) << "\ntask_continue: " << task_continue_counter;
    LOG(debug) << "resume_execution() call times distribution: ";
    LOG(debug) << "\tresume 1: " << resume1;
    LOG(debug) << "\tresume 2: " << resume2;
    LOG(debug) << "\tresume 3: " << resume3;
    LOG(debug) << "\tresume 4: " << resume4;
    LOG(debug) << "\tresume 5: " << resume5;
    LOG(debug) << "\toverall_resume_counter: " << overall_resume_counter;
  #endif
  #endif


  #if XDEBUG_PATCHING_OUTPUT
  LOG(debug) << "unpatched syscall: ";
  cout << "unpatched syscall: " << endl;
  for(const auto& pair : before_patching) {
    int syscallno = pair.first;
    LOG(debug) << syscall_name(syscallno, SupportedArch::x86_64) << " (" << syscallno << "): ";
    cout << syscall_name(syscallno, SupportedArch::x86_64) << " (" << syscallno << "): ";
    // for (double duration : pair.second) {
    //   cout << duration << ", ";
    // }
    // cout << endl;
    // find the median value in the vector
    vector<double> durations = pair.second;
    sort(durations.begin(), durations.end());
    double median;
    if (durations.size() % 2 == 0) {
      median = (durations[durations.size() / 2 - 1] + durations[durations.size() / 2]) / 2;
    } else {
      median = durations[durations.size() / 2];
    }
    LOG(debug) << median << " ms";
    cout << median << " ms" << endl;
  }
  #endif

  return res;
}
