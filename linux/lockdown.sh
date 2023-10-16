#!/usr/bin/env bash


check_crontab() {
	for user in $(cut -f1 -d: /etc/passwd); do echo "###### $user crontab is:"; cat /var/spool/cron/{crontabs/$user,$user} 2>/dev/null; done >> sysinfo.txt
    # if they create a bad user that runs things on an interval, we will know >:)
}

enumerate() {
	# enumerate system
	date -u  >> sysinfo.txt
	uname -a >> sysinfo.txt

	# Added in error testing, who knows what gets borked
	# per https://www.linux.org/docs/man5/os-release.html
	# /usr/lib/os-release should be the fallback

	if . /etc/os-release ; then
		OS=$NAME
	else
		. /usr/lib/os-release
	    OS=$NAME
	fi

	echo "OS is $ID" >> sysinfo.txt
	lscpu    >> sysinfo.txt
	lsblk    >> sysinfo.txt
	ip a     >> sysinfo.txt
	sudo netstat -auntp >>sysinfo.txt
	df       >> sysinfo.txt
	ls -latr /var/acc >> sysinfo.txt
	sudo ls -latr /var/log/* >> sysinfo.txt
	sudo ls -la /etc/syslog >> sysinfo.txt
	check_crontab
	cat /etc/crontab >> sysinfo.txt
	ls -la /etc/cron.* >> sysinfo.txt
	sestatus >> sysinfo.txt
	getenforce >> sysinfo.txt
	sudo cat /root/.bash_history >> sysinfo.txt
	cat ~/.bash_history >> sysinfo.txt
	cat /etc/group >> sysinfo.txt
	cat /etc/passwd >> sysinfo.txt

	# If Debian or Ubuntu (or Arch if we add support), then ufw is installed
	# ufw = Uncomplicated Firewall - https://help.ubuntu.com/community/UFW
	if [ "$OS" = "Ubuntu" ]; then
		ufw-status=$(sudo ufw status)
		echo "ufw $ufw-status" >> sysinfo.txt

	elif [ "$OS" = "Debian" ]; then
		ufw-status=$(sudo ufw status)
		echo "ufw $ufw-status" >> sysinfo.txt

	fi
}

backup_admin() {
	# create good tigers :thumbs_up:
	adduser --disabled-password --gecos "" goodtiger || echo "User Exists"
	adduser --disabled-password --gecos "" goodtiger2 || echo "User Exists"
	usermod -aG sudo goodtiger
	usermod -aG sudo goodtiger2
}

list_users() {
    cat /etc/passwd | cut -d: -f1 > user_list.txt
}

change_passwords() {
    	# change passwords to be STORNK
    	echo "SKIPPING BLUE-TEAM PASSWORD CHANGE"
	for i in `cat user_list.txt`
	do
		if [ "$i" != "blue-team" ]; then
			PASS=$(tr -dc A-Za-z0-9 < /dev/urandom | head -c 31)
			echo "Changing password for $i"
			echo "$i,$PASS" >>  userlist.txt
			echo -e "$PASS\n$PASS" | passwd $i
		else
			echo "NOT changing password for $i"
		fi
	done
}

check_repositories() {

	currDate=$(date)

	if . /etc/os-release ; then
                OS=$NAME
        else
                . /usr/lib/os-release
                OS=$NAME
    fi

	if [ "$OS" = "Ubuntu" ]; then
		if . /etc/apt/sources.list ; then
			cp /etc/apt/sources.list $(currDate)-sources.list # store bakup
		else
			echo "/etc/apt/sources.list Not Found!"
			echo "Attempting to create new source list"
		fi
		# /etc/apt/sources.list.d is a dir, need to check size before copying
		# 4.0K is the size of empty

		sourceDirSize=`du -sh /etc/apt/sources.list.d | cut -f1` #removes the tab by default

		if [ "$sourceDirSize" != "4.0K" ]; then
			echo "!!!!! Check /etc/apt/sources.list.d for any suspicious sources"
		else
			echo "/etc/apt/sources.list.d not found"
		fi
    fi
}

install_tools() {

	# Added in error testing, who knows what gets borked
	# per https://www.linux.org/docs/man5/os-release.html
	# /usr/lib/os-release should be the fallback

	if . /etc/os-release ; then
	        OS=$NAME
	else
	        . /usr/lib/os-release
	        OS=$NAME
	fi

	echo "$OS installing tools"

	if [ "$OS" = "Ubuntu" ]; then
		apt -y install net-tools fail2ban tripwire clamav inotify-tools epel-release

	elif [ "$OS" = "Debian" ]; then
		apt -y install net-tools fail2ban tripwire clamav inotify-tools epel-release

	elif [ "$OS" = "CentOS Linux" ];then
		yum -y install net-tools fail2ban tripwire clamav inotify-tools epel-release

	else
	echo "Not Ubuntu, Debian or CentOS, install tools manually"

	fi
}

enable_firewall() {
	ufw enable
	ufw default deny incoming
	ufw default allow outgoing
	ufw deny 1337
}

disable_guest_login() {
	gpasswd -d guest sudo
	sed -i -e 's/^.*[SeatDefaults].*$/[SeatDefaults] allow-guest=false/' /etc/lightdm/lightdm.conf
}

file_rw_perms() {
	chmod 644 /etc/passwd
	chmod 640 /etc/shadow
	chmod 644 /etc/group
	chmod 640 .bash_history
	# set HOSTS file to defaults
	chmod 777 /etc/hosts
	cp /etc/hosts ~/Desktop/backups/
	echo > /etc/hosts
	echo -e "127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
	chmod 644 /etc/hosts
}

harden_ssm() {
 	# sed -i '$ a\tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0' /etc/fstab
 	awk '{tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0 >> /etc/fstab}'
}

common_vuln() {
	# prevent shellshock bash vulnerability
	env i='() { :;}; echo Your system is Bash vulnerable' bash -c "echo Bash vulnerability test"
	# disable irqbalance
	cp /etc/default/irqbalance ~/Desktop/backups/
	echo > /etc/default/irqbalance
	echo -e "#Configuration for the irqbalance daemon\n\n#Should irqbalance be enabled?\nENABLED=\"0\"\n#Balance the IRQs     only once?\nONESHOT=\"0\"" >> /etc/default/irqbalance
}

check_root() {
	# displays all accounts with UID set to 0
	awk -F: '($3 == "0") {print}' /etc/passwd
 	# expected: root:x:0:0:root:/root:/bin/bash
}

update_system() {
	apt update -y
	apt dist-upgrade -y
}

main() {
	update_system
	install_tools
	enumerate
	backup_admin
	list_users
	change_passwords
 	enable_firewall
  	disable_guest_login
   	file_rw_perms
     	harden_ssm
      	common_vuln
}

main
