#!/bin/bash


pip install virtualenv
cd $home
sudo apt install python3.10-venv
python3 -m venv myenv
source myenv/bin/activate
pip install scapy
pip install selenium
cd sniffer

rm *.png
sudo rm urls.txt
sudo -E $HOME/myenv/bin/python $HOME/sniffer/info2.py


sudo chmod u+wrx urls.txt

$HOME/myenv/bin/python selenium1.py






