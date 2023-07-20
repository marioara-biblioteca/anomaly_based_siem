#!/bin/bash
files=$(ls /opt/zeek/logs/current/*.log)
for file in $files
do
        cp "$file" /home/cristiana/pyqt/two_windows/logs/current/
        file=$(echo $file | cut -f 6 -d'/')
        file="/home/cristiana/pyqt/two_windows/logs/current/$file"
        first_line=$(head -n 1 $file)
        if [[ "$first_line" == "#"* ]]; then
                sed -i -e '1,6d;8d' $file && sed -i '$d' $file  && sed -i -e 's/#fields\t//g' $file
        fi
done
# rm /home/cristiana/pyqt/two_windows/logs/capfile*