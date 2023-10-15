#!/usr/binenv/bash


function check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "this script requires root privileges..." 1>&2
    exit 1
  fi
}

SSHD_CONF="/etc/ssh/sshd_config"

function sshd_config_check() {
  if [[ -f $SSHD_CONF ]]; then
    echo "sshd_config found"
  else
    echo -n "sshd_config not found at $SSHD_CONF, please specify path: "
    read SSHD_CONF
    sshd_config_check
  fi
}

function backup_sshd_config() {
  cp $SSHD_CONF .
  echo "backed up sshd_config to $(pwd)"
}

function change_protocol() {
  sed -i -e 's/^.*Protocol.*$/Protocol 2/' $SSHD_CONF
}

function root_login() {
  sed -i -e 's/^.*PermitRootLogin.*$/PermitRootLogin no/' $SSHD_CONF
}

function ssh_port() {
  echo -n "desired ssh port (1-65535): "
  read port_number
  if [ $port_number -gt 0 -a $port_number -lt 65536  ] ; then
    sed -i -e "s/^.*Port.*$/Port $port_number/" $SSHD_CONF
  else 
    echo "desired ssh port (1-65535): "
    ssh_port
  fi  
}

function max_auth() {
  echo -n "max auth attempts (1-10): "
  read auth_attempts
  if [ $auth_attempts -gt 0 -a $auth_attempts -lt 11  ] ; then
    sed -i -e "s/^.*MaxAuthTries.*$/MaxAuthTries $auth_attempts/" $SSHD_CONF
  else 
    echo "max auth attempts (1-10): "
    max_auth
  fi  
}

function empty_passwords() {
  sed -i -e 's/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/' $SSHD_CONF
}

function login_gt() {
  echo -n "login grace period (5-120): "
  read grace_time
  if [ $grace_time -gt 4 -a $grace_time -lt 121  ] ; then
    sed -i -e "s/^.*LoginGraceTime.*$/LoginGraceTime $grace_time/" $SSHD_CONF
  else
    echo "login grace period (5-120): "
    login_gt
  fi
}

function disable_pw() {
  sed -i -e 's/^.*PasswordAuthenticat.*$/PasswordAuthentication no/g' $SSHD_CONF
}

function disable_rhosts() {
  sed -i -e 's/^.*IgnoreRhosts.*$/IgnoreRhosts yes/' $SSHD_CONF
}

function warning_banner() {
  touch /etc/ssh/sshd_banner
  cat >/etc/ssh/sshd_banner <<EOF
   EYYY WHADDAYA DOIN IM WALKIN ERE
EOF
vi /etc/ssh/sshd_banner
sed -i -e 's=^.*Banner.*$=Banner /etc/ssh/sshd_banner=' $SSHD_CONF
}

function quick_config() {
  check_root
  sshd_config_check
  backup_sshd_config
  change_protocol
  root_login
  ssh_port
  max_auth
  empty_passwords
  login_gt
  disable_pw
  disable_rhosts
  warning_banner
}

quick_config
echo "done! restart sshd..."
