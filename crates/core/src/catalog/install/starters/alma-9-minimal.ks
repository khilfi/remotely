# AlmaLinux 9, minimal: one admin user in wheel with your SSH key, root locked, LVM over the whole disk, DHCP.
# Installs from the ISO itself. A starter from Remotely: copy it to change it. The admin password, picked from
# the vault, goes in as a SHA-512 hash when a VM is deployed.
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
%end
