#!/usr/bin/env sh
set -x
TGT="./123321testdir"
if [ -e $TGT ] && [ -d $TGT ]; then
  rm -r $TGT
fi
mkdir -p $TGT/inner_test_dir
if [ -e listlong ]; then
  cp ./listlong $TGT/listlong
fi

touch $TGT/inner_test_dir/inner_file

touch $TGT/regular_zero_stickybit
chmod 1750 $TGT/regular_zero_stickybit

touch $TGT/regular_normal
echo "testtesttest" | tee $TGT/regular_normal
chmod 753 $TGT/regular_normal

touch $TGT/regular_no_names
chown 1:2 $TGT/regular_no_names

touch $TGT/regular_ютф8

ln --symbolic regular_normal $TGT/symlink

ln $TGT/regular_normal $TGT/hardlink

cd $TGT || exit
ls -l
if [ -e listlong ]; then
  ./listlong
fi
echo "====="
cd - || exit

ls -l /dev | head -n 30
if [ -e listlong ]; then
  ./listlong /dev | head -n 30
fi

rm -rf $TGT
