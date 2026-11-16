# AlmaLinux 9, minimal: one admin user in wheel with your SSH key, root locked, LVM over the whole disk, DHCP.
# Installs from the ISO itself. A starter from Remotely: copy it to change it. The admin password, picked from
# the vault, goes in as a SHA-512 hash when a VM is deployed. open-vm-tools (VMware Tools) lets Workstation learn the
# guest's address on a bridged network, and on VirtualBox it doesn't start. The minimal ISO doesn't carry it, and
# Anaconda stops on a listed package its source lacks, so %post installs it when it isn't there yet: from the mirrors
# when the network reaches them, never failing the install.
text
lang en_US.UTF-8
keyboard --xlayouts='us'
timezone Etc/UTC --utc
network --bootproto=dhcp --device=link --activate --hostname="{{hostname}}"
cdrom
rootpw --lock
user --name=sysadmin --groups=wheel --iscrypted --password="{{password.admin}}"
sshkey --username=sysadmin "{{ssh_key.admin}}"
firstboot --disable
selinux --enforcing
firewall --enabled --service=ssh
services --enabled=sshd
zerombr
clearpart --all --initlabel
autopart --type=lvm
bootloader --timeout=1
reboot --eject

%packages
@^minimal-environment
openssh-server
%end

%post
echo "Installed by Remotely from an install config (AlmaLinux 9)." > /etc/motd
rpm -q open-vm-tools >/dev/null 2>&1 || timeout 300 dnf -y install open-vm-tools || true
%end
