#!/bin/bash

c_compiler="/fuzzing/elafuzz-plus/afl-clang-fast"
cxx_compiler="/fuzzing/elafuzz-plus/afl-clang-fast++"
work_dir="/fuzzing/benchmark"
fuzzer_dir="/fuzzing/elafuzz-plus"

export AFL_LLVM_INSTRUMENT=CLASSIC



# first set

cd "$work_dir"/unibench/Bento4-1.5.1-628
mkdir build && cd build
CC="$c_compiler" CXX="$cxx_compiler" cmake ..
make -j8
cd .. && mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/Bento4-1.5.1-628/build/mp42aac

cd "$work_dir"/unibench/flvmeta-1.2.1
mkdir build && cd build
CC="$c_compiler" CXX="$cxx_compiler" cmake ..
make -j8
cd .. && mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/flvmeta-1.2.1/build/src/flvmeta

cd "$work_dir"/unibench/jhead-3.00
CC="$c_compiler" CXX="$cxx_compiler" make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/jhead-3.00/jhead

cd "$work_dir"/unibench/jq-1.5
CC="$c_compiler" CXX="$cxx_compiler" ./configure --disable-shared
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/jq-1.5/jq

cd "$work_dir"/unibench/lame-3.99.5
CC="$c_compiler" CXX="$cxx_compiler" ./configure --disable-shared
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/lame-3.99.5/frontend/lame

cd "$work_dir"/unibench/mp3gain-1.5.2
sed -i "s:gcc:$c_compiler:g" Makefile
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/mp3gain-1.5.2/mp3gain

cd "$work_dir"/unibench/mujs-1.0.2
CC="$c_compiler" CXX="$cxx_compiler" make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/mujs-1.0.2/build/release/mujs

cd "$work_dir"/unibench/ncurses-6.1
CC="$c_compiler" CXX="$cxx_compiler" ./configure --disable-shared
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/ncurses-6.1/progs/tic

cd "$work_dir"/unibench/tcpdump-4.8.1
apt-get -y install libpcap-dev
CC="$c_compiler" CXX="$cxx_compiler" ./configure
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/tcpdump-4.8.1/tcpdump

cd "$work_dir"/unibench/xpdf-4.00
mkdir build && cd build
CC="$c_compiler" CXX="$cxx_compiler" cmake ..
make -j8
cd .. && mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/xpdf-4.00/build/xpdf/pdftotext

# second set

cd "$work_dir"/oss-fuzz/INCHI-1-SRC/INCHI_EXE/inchi-1/gcc
sed -i "s:= gcc:= $c_compiler:g" makefile
sed -i "s:= g++:= $cxx_compiler:g" makefile
make -j8
cd "$work_dir"/oss-fuzz/INCHI-1-SRC && mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/INCHI-1-SRC/INCHI_EXE/bin/Linux/inchi-1

cd "$work_dir"/oss-fuzz/binutils-gdb-master
CC="$c_compiler" CXX="$cxx_compiler" ./configure --disable-gdb --disable-gdbserver --disable-gdbsupport \
        --disable-libdecnumber --disable-readline --disable-sim \
        --disable-libbacktrace --disable-gas --disable-ld --disable-werror \
      --enable-targets=all
make -j8
mkdir fuzz_obj && cd fuzz_obj
"$fuzzer_dir"/shmtofile
cd .. && cp -r fuzz_obj fuzz_nm
cd fuzz_obj && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/binutils-gdb-master/binutils/objdump
cd ../fuzz_nm && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/binutils-gdb-master/binutils/nm-new

cd "$work_dir"/oss-fuzz/espeak-ng
./autogen.sh
CC="$c_compiler" CXX="$cxx_compiler" ./configure --disable-shared
make -j8
cp -r ./espeak-ng-data /usr/local/share/
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/espeak-ng/src/espeak-ng

cd "$work_dir"/oss-fuzz/ffmpeg
CC="$c_compiler" CXX="$cxx_compiler" ./configure --disable-shared
cd ffbuild
sed -i "24,31s:gcc:$c_compiler:" config.mak
sed -i "25s:g++:$cxx_compiler:" config.mak
cd ..
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/ffmpeg/ffmpeg

cd "$work_dir"/oss-fuzz/jsonnet
mkdir build && cd build
CC="$c_compiler" CXX="$cxx_compiler" cmake ..
make -j8
cd .. && mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/jsonnet/build/jsonnetfmt

cd "$work_dir"/oss-fuzz/libsndfile
mkdir build && cd build
CC="$c_compiler" CXX="$cxx_compiler" cmake ..
make -j8
cd .. && mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/libsndfile/build/sndfile-to-text

cd "$work_dir"/oss-fuzz/elfutils
autoreconf -i -f
CC="$c_compiler" CXX="$cxx_compiler" ./configure --enable-maintainer-mode --disable-libdebuginfod --disable-debuginfod
make -j8
export LD_LIBRARY_PATH+="$work_dir"/oss-fuzz/elfutils/libdw
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/elfutils/src/readelf

cd "$work_dir"/oss-fuzz/exiv2
./ci/install_dependencies.sh
mkdir build && cd build
CC="$c_compiler" CXX="$cxx_compiler" cmake -DEXIV2_ENABLE_PNG=ON -DEXIV2_ENABLE_WEBREADY=ON -DEXIV2_ENABLE_CURL=OFF -DEXIV2_ENABLE_BMFF=ON -DEXIV2_TEAM_WARNINGS_AS_ERRORS=ON -DBUILD_SHARED_LIBS=OFF -DEXIV2_ENABLE_INIH=OFF ..
make -j8
cd .. && mkdir fuzz_exiv2 && cd fuzz_exiv2
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/exiv2/build/bin/exiv2

cd "$work_dir"/oss-fuzz/ghostpdl-10.02.1
./autogen.sh
CC="$c_compiler" CXX="$cxx_compiler" ./configure
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/ghostpdl-10.02.1/bin/gpdf

# third set

cd "$work_dir"/unibench/cflow-1.6
CC="$c_compiler" CXX="$cxx_compiler" ./configure
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/unibench/cflow-1.6/src/cflow

cd "$work_dir"/oss-fuzz/vim
CC="$c_compiler" CXX="$cxx_compiler" ./configure
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/vim/src/vim

cd "$work_dir"/oss-fuzz/sqlite3
CC="$c_compiler" CXX="$cxx_compiler" ./configure --enable-shared=no
make -j8
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/sqlite3/sqlite3

cd "$work_dir"/oss-fuzz/libredwg
sh ./autogen.sh
CC="$c_compiler" CXX="$cxx_compiler" ./configure --disable-shared --disable-bindings --enable-release
make
mkdir fuzz && cd fuzz
"$fuzzer_dir"/shmtofile && "$fuzzer_dir"/analysis_test "$work_dir"/oss-fuzz/libredwg/programs/dwg2dxf