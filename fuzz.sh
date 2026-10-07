#!/bin/bash

fuzzer_path="/fuzzing/elafuzz-plus/afl-fuzz"
ass_path="/fuzzing/elafuzz-plus/assist_addedges"
seed_dir="/fuzzing/seeds/general_evaluation"
exiv2_seed="/fuzzing/seeds/seed_amount/jpg_100"
count=0
cpu_free=20
shm=300

export AFL_NO_UI=1
export LD_LIBRARY_PATH+=/fuzzing/benchmark/oss-fuzz/elfutils/libdw

mp4_path="/fuzzing/benchmark/unibench/Bento4-1.5.1-628/build/mp42aac"
mp4_out="/fuzzing/benchmark/unibench/Bento4-1.5.1-628/fuzz"
cd $mp4_out && cp mp42aac /fuzzing/benchmark/unibench/Bento4-1.5.1-628/build/
nohup timeout 24h $fuzzer_path -i $seed_dir/mp4 -o $mp4_out/outMay_$count  -b $cpu_free -H $shm -d $mp4_path @@ /dev/null > $mp4_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c mp42aac ./outMay_$count/default/mp42aac.predecessor @@ /dev/null > $mp4_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

cflow_path="/fuzzing/benchmark/unibench/cflow-1.6/src/cflow"
cflow_out="/fuzzing/benchmark/unibench/cflow-1.6/fuzz"
cd $cflow_out && cp cflow /fuzzing/benchmark/unibench/cflow-1.6/src
nohup timeout 24h $fuzzer_path -i $seed_dir/cflow -o $cflow_out/outMay_$count  -b $cpu_free -H $shm -d $cflow_path @@ > $cflow_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c cflow ./outMay_$count/default/cflow.predecessor @@ > $cflow_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

flv_path="/fuzzing/benchmark/unibench/flvmeta-1.2.1/build/src/flvmeta"
flv_out="/fuzzing/benchmark/unibench/flvmeta-1.2.1/fuzz"
cd $flv_out && cp flvmeta /fuzzing/benchmark/unibench/flvmeta-1.2.1/build/src
nohup timeout 24h $fuzzer_path -i $seed_dir/flv -o $flv_out/outMay_$count  -b $cpu_free -H $shm -d $flv_path @@ > $flv_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c flvmeta ./outMay_$count/default/flvmeta.predecessor @@ > $flv_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

jhead_path="/fuzzing/benchmark/unibench/jhead-3.00/jhead"
jhead_out="/fuzzing/benchmark/unibench/jhead-3.00/fuzz"
cd $jhead_out && cp jhead /fuzzing/benchmark/unibench/jhead-3.00
nohup timeout 24h $fuzzer_path -i $seed_dir/jhead -o $jhead_out/outMay_$count  -b $cpu_free -H $shm -d $jhead_path @@ > $jhead_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c jhead ./outMay_$count/default/jhead.predecessor @@ > $jhead_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

jq_path="/fuzzing/benchmark/unibench/jq-1.5/jq"
jq_out="/fuzzing/benchmark/unibench/jq-1.5/fuzz"
cd $jq_out && cp jq /fuzzing/benchmark/unibench/jq-1.5
nohup timeout 24h $fuzzer_path -i $seed_dir/json -o $jq_out/outMay_$count  -b $cpu_free -H $shm -d $jq_path . @@ > $jq_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c jq ./outMay_$count/default/jq.predecessor . @@ > $jq_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

lame_path="/fuzzing/benchmark/unibench/lame-3.99.5/frontend/lame"
lame_out="/fuzzing/benchmark/unibench/lame-3.99.5/fuzz"
cd $lame_out && cp lame /fuzzing/benchmark/unibench/lame-3.99.5/frontend
nohup timeout 24h $fuzzer_path -i $seed_dir/lame3.99.5 -o $lame_out/outMay_$count  -b $cpu_free -H $shm -d $lame_path @@ /dev/null > $lame_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c lame ./outMay_$count/default/lame.predecessor @@ /dev/null > $lame_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

mp3_path="/fuzzing/benchmark/unibench/mp3gain-1.5.2/mp3gain"
mp3_out="/fuzzing/benchmark/unibench/mp3gain-1.5.2/fuzz"
cd $mp3_out && cp mp3gain /fuzzing/benchmark/unibench/mp3gain-1.5.2
nohup timeout 24h $fuzzer_path -i $seed_dir/mp3 -o $mp3_out/outMay_$count  -b $cpu_free -H $shm -d $mp3_path @@ > $mp3_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c mp3gain ./outMay_$count/default/mp3gain.predecessor @@ > $mp3_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

mujs_path="/fuzzing/benchmark/unibench/mujs-1.0.2/build/release/mujs"
mujs_out="/fuzzing/benchmark/unibench/mujs-1.0.2/fuzz"
cd $mujs_out && cp mujs /fuzzing/benchmark/unibench/mujs-1.0.2/build/release
nohup timeout 24h $fuzzer_path -i $seed_dir/mujs -o $mujs_out/outMay_$count  -b $cpu_free -H $shm -d $mujs_path @@ > $mujs_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c mujs ./outMay_$count/default/mujs.predecessor @@ > $mujs_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

tic_path="/fuzzing/benchmark/unibench/ncurses-6.1/progs/tic"
tic_out="/fuzzing/benchmark/unibench/ncurses-6.1/fuzz"
cd $tic_out && cp tic /fuzzing/benchmark/unibench/ncurses-6.1/progs
nohup timeout 24h $fuzzer_path -i $seed_dir/text -o $tic_out/outMay_$count  -b $cpu_free -H $shm -d $tic_path -o /dev/null @@ > $tic_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c tic ./outMay_$count/default/tic.predecessor -o /dev/null @@ > $tic_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

tcp_path="/fuzzing/benchmark/unibench/tcpdump-4.8.1/tcpdump"
tcp_out="/fuzzing/benchmark/unibench/tcpdump-4.8.1/fuzz"
cd $tcp_out && cp tcpdump /fuzzing/benchmark/unibench/tcpdump-4.8.1
nohup timeout 24h $fuzzer_path -i $seed_dir/tcpdump100 -o $tcp_out/outMay_$count  -b $cpu_free -H $shm -d $tcp_path -e -vv -nr @@ > $tcp_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c tcpdump ./outMay_$count/default/tcpdump.predecessor -e -vv -nr @@ > $tcp_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

xpdf_path="/fuzzing/benchmark/unibench/xpdf-4.00/build/xpdf/pdftotext"
xpdf_out="/fuzzing/benchmark/unibench/xpdf-4.00/fuzz"
cd $xpdf_out && cp pdftotext /fuzzing/benchmark/unibench/xpdf-4.00/build/xpdf
nohup timeout 24h $fuzzer_path -i $seed_dir/pdf -o $xpdf_out/outMay_$count  -b $cpu_free -H $shm -d $xpdf_path @@ /dev/null > $xpdf_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c pdftotext ./outMay_$count/default/pdftotext.predecessor @@ /dev/null > $xpdf_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

inchi_path="/fuzzing/benchmark/oss-fuzz/INCHI-1-SRC/INCHI_EXE/bin/Linux/inchi-1"
inchi_out="/fuzzing/benchmark/oss-fuzz/INCHI-1-SRC/fuzz"
cd $inchi_out && cp inchi-1 /fuzzing/benchmark/oss-fuzz/INCHI-1-SRC/INCHI_EXE/bin/Linux
nohup timeout 24h $fuzzer_path -i $seed_dir/text -o $inchi_out/outMay_$count  -b $cpu_free -H $shm -d $inchi_path @@ /dev/null /dev/null /dev/null > $inchi_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c inchi-1 ./outMay_$count/default/inchi-1.predecessor @@ /dev/null /dev/null /dev/null > $inchi_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

obj_path="/fuzzing/benchmark/oss-fuzz/binutils-gdb-master/binutils/objdump"
obj_out="/fuzzing/benchmark/oss-fuzz/binutils-gdb-master/fuzz_obj"
cd $obj_out && cp objdump /fuzzing/benchmark/oss-fuzz/binutils-gdb-master/binutils
nohup timeout 24h $fuzzer_path -i $seed_dir/obj -o $obj_out/outMay_$count  -b $cpu_free -H $shm -d $obj_path -S @@ > $obj_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c objdump ./outMay_$count/default/objdump.predecessor -S @@ > $obj_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

nm_path="/fuzzing/benchmark/oss-fuzz/binutils-gdb-master/binutils/nm-new"
nm_out="/fuzzing/benchmark/oss-fuzz/binutils-gdb-master/fuzz_nm"
cd $nm_out && cp nm-new /fuzzing/benchmark/oss-fuzz/binutils-gdb-master/binutils
nohup timeout 24h $fuzzer_path -i $seed_dir/nm -o $nm_out/outMay_$count  -b $cpu_free -H $shm -d $nm_path -A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@ > $nm_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c nm-new ./outMay_$count/default/nm-new.predecessor -A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@ > $nm_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

espeak_path="/fuzzing/benchmark/oss-fuzz/espeak-ng/src/espeak-ng"
espeak_out="/fuzzing/benchmark/oss-fuzz/espeak-ng/fuzz"
cd $espeak_out && cp espeak-ng /fuzzing/benchmark/oss-fuzz/espeak-ng/src
nohup timeout 24h $fuzzer_path -i $seed_dir/espeak_txt -o $espeak_out/outMay_$count  -b $cpu_free -H $shm -d $espeak_path -f @@ -w /dev/null > $espeak_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c espeak-ng ./outMay_$count/default/espeak-ng.predecessor -f @@ -w /dev/null > $espeak_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

ffmpeg_path="/fuzzing/benchmark/oss-fuzz/ffmpeg/ffmpeg"
ffmpeg_out="/fuzzing/benchmark/oss-fuzz/ffmpeg/fuzz"
cd $ffmpeg_out && cp ffmpeg /fuzzing/benchmark/oss-fuzz/ffmpeg
nohup timeout 24h $fuzzer_path -i $seed_dir/ffmpeg100 -o $ffmpeg_out/outMay_$count  -b $cpu_free -H $shm -m none -d $ffmpeg_path -y -i @@ -c:v mpeg4 -c:a copy -f mp4 /dev/null > $ffmpeg_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c ffmpeg ./outMay_$count/default/ffmpeg.predecessor -y -i @@ -c:v mpeg4 -c:a copy -f mp4 /dev/null > $ffmpeg_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

jsonnet_path="/fuzzing/benchmark/oss-fuzz/jsonnet/build/jsonnetfmt"
jsonnet_out="/fuzzing/benchmark/oss-fuzz/jsonnet/fuzz"
cd $jsonnet_out && cp jsonnetfmt /fuzzing/benchmark/oss-fuzz/jsonnet/build
nohup timeout 24h $fuzzer_path -i $seed_dir/json -o $jsonnet_out/outMay_$count  -b $cpu_free -H $shm -d $jsonnet_path -i @@ > $jsonnet_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c jsonnetfmt ./outMay_$count/default/jsonnetfmt.predecessor -i @@ > $jsonnet_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

snd_path="/fuzzing/benchmark/oss-fuzz/libsndfile/build/sndfile-to-text"
snd_out="/fuzzing/benchmark/oss-fuzz/libsndfile/fuzz"
cd $snd_out && cp sndfile-to-text /fuzzing/benchmark/oss-fuzz/libsndfile/build
nohup timeout 24h $fuzzer_path -i $seed_dir/wav -o $snd_out/outMay_$count  -b $cpu_free -H $shm -d $snd_path @@ /dev/null > $snd_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c sndfile-to-text ./outMay_$count/default/sndfile-to-text.predecessor @@ /dev/null > $snd_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

elf_path="/fuzzing/benchmark/oss-fuzz/elfutils/src/readelf"
elf_out="/fuzzing/benchmark/oss-fuzz/elfutils/fuzz"
cd $elf_out && cp readelf /fuzzing/benchmark/oss-fuzz/elfutils/src
nohup timeout 24h $fuzzer_path -i $seed_dir/nm -o $elf_out/outMay_$count  -b $cpu_free -H $shm -m none -d $elf_path -a @@ > $elf_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c readelf ./outMay_$count/default/readelf.predecessor -a @@ > $elf_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

exiv2_path="/fuzzing/benchmark/oss-fuzz/exiv2/build/bin/exiv2"
exiv2_out="/fuzzing/benchmark/oss-fuzz/exiv2/fuzz_exiv2"
cd $exiv2_out && cp exiv2 /fuzzing/benchmark/oss-fuzz/exiv2/build/bin
nohup timeout 24h $fuzzer_path -i $exiv2_seed -o $exiv2_out/outMay_$count  -b $cpu_free -H $shm -d $exiv2_path @@ > $exiv2_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c exiv2 ./outMay_$count/default/exiv2.predecessor @@ > $exiv2_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

gpdf_path="/fuzzing/benchmark/oss-fuzz/ghostpdl-10.02.1/bin/gpdf"
gpdf_out="/fuzzing/benchmark/oss-fuzz/ghostpdl-10.02.1/fuzz"
cd $gpdf_out && cp gpdf /fuzzing/benchmark/oss-fuzz/ghostpdl-10.02.1/bin
nohup timeout 24h $fuzzer_path -i $seed_dir/pdf -o $gpdf_out/outMay_$count  -b $cpu_free -H $shm -m none -d $gpdf_path -dNOPAUSE @@ > $gpdf_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c gpdf ./outMay_$count/default/gpdf.predecessor -dNOPAUSE @@ > $gpdf_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))

dwg_path="/fuzzing/benchmark/oss-fuzz/libredwg/programs/dwg2dxf"
dwg_out="/fuzzing/benchmark/oss-fuzz/libredwg/fuzz"
cd $dwg_out && cp dwg2dxf /fuzzing/benchmark/oss-fuzz/libredwg/programs
nohup timeout 24h $fuzzer_path -i $seed_dir/dwg -o $dwg_out/outMay_$count  -b $cpu_free -H $shm -d $dwg_path @@ -o /dev/null > $dwg_out/fuzzeroutMay_$count.log 2>&1 &
sleep 10
nohup timeout 24h $ass_path -o ass_$count -s $shm -q ./outMay_$count/default/queue -c dwg2dxf ./outMay_$count/default/dwg2dxf.predecessor @@ -o /dev/null > $dwg_out/assoutMay_$count.log 2>&1 &
((cpu_free++))
((shm+=10))