//
// Created by Xiao Luo on 4/3/2024.
//

#include "CRIU.h"
#include "util.h"
#include <criu.h>

using namespace std;

namespace rr {

CRIU::CRIU() {}

CRIU::~CRIU() {}

void CRIU::check_point() {
#if CHECKPOINT
  // checkpoint here
  // use criu to checkpoint the process with pid tracee_pid
  string image_dir = "/home/criu/images/rr_record";
  int fd = open(image_dir.c_str(), O_DIRECTORY);

  criu_init_opts();
  criu_set_images_dir_fd(fd);
  // double check here
  criu_set_pid(tracee_pid);
  criu_set_shell_job(true);
  criu_set_log_level(4);
  criu_set_log_file("checkpoint.log");
  criu_set_leave_running(true);
  int ret = criu_dump();

  if (ret < 0) {
    cout << "criu dump failed" << endl;
  }
  else {
    cout << "criu dump succeeded" << endl;
  }
#endif
}

void CRIU::restore_state() {
#if CHECKPOINT
  criu_restore();
#endif
}

} // namespace rr
