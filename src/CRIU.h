//
// Created by Xiao Luo on 4/3/2024.
//

#ifndef RR_CRIU_H
#define RR_CRIU_H

#include <pthread.h>
#include <stdint.h>

namespace rr {

/**
 * CompressedWriter opens an output file and writes compressed blocks to it.
 * Blocks of a fixed but unspecified size (currently 1MB) are compressed.
 * Each block of compressed data is written to the file preceded by two
 * 32-bit words: the size of the compressed data (excluding block header)
 * and the size of the uncompressed data, in that order. See BlockHeader below.
 *
 * We use multiple threads to perform compression. The threads are
 * responsible for the actual data writes. The thread that creates the
 * CompressedWriter is the "producer" thread and must also be the caller of
 * 'write'. The producer thread may block in 'write' if 'buffer_size' bytes are
 * being compressed.
 *
 * Each data block is compressed independently using zlib.
 */
class CRIU {
public:
  CRIU();
  ~CRIU();

  void check_point();
  void restore_state();
};

} // namespace rr

#endif // RR_CRIU_H
