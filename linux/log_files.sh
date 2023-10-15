log_files() {
	# see open files that are using network
	echo "OPEN FILES" >> file_logs.txt
	lsof -i -n -P >> file_logs.txt
	# check for any files for users that should not be administrators
	echo "ADMINISTRATOR FILES" >> file_logs.txt
	ls -a /etc/sudoers.d >> file_logs.txt
}

main() {
  log_files
}

main
