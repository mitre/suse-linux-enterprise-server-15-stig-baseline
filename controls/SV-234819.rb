control 'SV-234819' do
  title 'SUSE operating systems with a basic input/output system (BIOS) must require authentication upon booting into single-user and maintenance modes.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Verify that the SUSE operating system has set an encrypted root password. 

Note: If the system does not use a BIOS this requirement is Not Applicable.

Check that the encrypted password is set for root with the following command:

> sudo cat /boot/grub2/grub.cfg | grep -i password 

password_pbkdf2 root grub.pbkdf2.sha512.10000.VeryLongString

If the root password entry does not begin with "password_pbkdf2", this is a finding.'
  desc 'fix', 'Note: If the system does not use a BIOS this requirement is Not Applicable.

Configure the SUSE operating system to encrypt the boot password.

Generate an encrypted (GRUB2) password for root with the following command:

> grub2-mkpasswd-pbkdf2
Enter Password:
Reenter Password:
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.MFU48934NJD84NF8NSD39993JDHF84NG

Using the hash from the output, modify the "/etc/grub.d/40_custom" file and add the following two lines to add a boot password for the root entry:

set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.VeryLongString

Generate an updated "grub.conf" file with the new password using the following commands:

> sudo grub2-mkconfig --output=/tmp/grub2.cfg
> sudo mv /tmp/grub2.cfg /boot/grub2/grub.cfg'
  impact 0.7
  tag check_id: 'C-38007r618726_chk'
  tag severity: 'high'
  tag gid: 'V-234819'
  tag rid: 'SV-234819r1137691_rule'
  tag stig_id: 'SLES-15-010190'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-37970r618727_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  grubfile = file(input('grub_conf_path'))

  describe grubfile do
    it { should exist }
  end

  superusers_account = grubfile.content.match(/set superusers="(?<superusers_account>\w+)"/)

  describe 'The GRUB superuser' do
    it "should be set in the GRUB config file ('#{grubfile}')" do
      expect(superusers_account).to_not be_nil, "No superuser account set in '#{grubfile}'"
    end
    unless superusers_account.nil?
      it 'should not contain easily guessable usernames' do
        expect(input('disallowed_grub_superusers')).to_not include(superusers_account[:superusers_account]), "Superuser account is set to easily guessable username '#{superusers_account[:superusers_account]}'"
      end
    end
  end
end
