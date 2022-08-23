#!/usr/bin/env bash

sudo apt-get install -y git whiptail #Installs packages which might be missing

PiSupplySwitchDir="Pi-Supply-Switch"
if [ -d "$PiSupplySwitchDir" ]; then
  whiptail --title "Installation aborted" --msgbox "$PiSupplySwitchDir already exists, please remove it and restart the installation" 8 78
  exit
else
  git clone https://github.com/PiSupply/Pi-Supply-Switch.git
fi

sudo mkdir /opt/piswitch

sudo cp $PiSupplySwitchDir/softshut.py /opt/piswitch
if [ ! -f /opt/piswitch/softshut.py ]; then
  whiptail --title "Installation aborted" --msgbox "There was a problem writing the softshut.py file" 8 78
  exit
fi
sudo cp $PiSupplySwitchDir/piswitch.service /etc/systemd/system
if [ ! -f /etc/systemd/system/piswitch.service ]; then
  whiptail --title "Installation aborted" --msgbox "There was a problem writing the piswitch.service file" 8 78
  exit
fi

sudo systemctl enable /etc/systemd/system/piswitch.service
whiptail --title "Installation complete" --msgbox "Pi Switch installation complete. The system will power off." 8 78
sudo poweroff
