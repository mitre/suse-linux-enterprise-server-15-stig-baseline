control 'SV-235008' do
  title 'The SUSE operating system SSH daemon public host key files must have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH
service may be compromised.'
  desc 'check', %q(Verify the SUSE operating system SSH daemon public host key files have mode "0644" or less permissive.

Note: SSH public key files may be found in other directories on the system depending on the installation.

The following command will find all SSH public key files on the system:

> find /etc/ssh -name 'ssh_host*key.pub' -exec stat -c "%a %n" {} \;

644 /etc/ssh/ssh_host_rsa_key.pub
644 /etc/ssh/ssh_host_dsa_key.pub
644 /etc/ssh/ssh_host_ecdsa_key.pub
644 /etc/ssh/ssh_host_ed25519_key.pub

If any file has a mode more permissive than "0644", this is a finding.)
  desc 'fix', 'Configure the SUSE operating system SSH daemon public host key files have mode "0644" or less permissive.

Note: SSH public key files may be found in other directories on the system depending on the installation.

Change the mode of public host key files under "/etc/ssh" to "0644" with the following command:

> sudo chmod 0644 /etc/ssh/ssh_host*key.pub'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-235008'
  tag rid: 'SV-235008r991589_rule'
  tag stig_id: 'SLES-15-040240'
  tag fix_id: 'F-38159r619294_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  ssh_host_key_dirs = input('ssh_host_key_dirs').join(' ')
  pub_keys = command("find #{ssh_host_key_dirs} -xdev -name '*.pub'").stdout.split("\n")
  mode = input('file_modes')['max'][:ssh_pub_key]
  failing_keys = pub_keys.select { |key| file(key).more_permissive_than?(mode) }

  describe 'All SSH public keys on the filesystem' do
    it "should be less permissive than #{mode}" do
      expect(failing_keys).to be_empty, "Failing keyfiles:\n\t- #{failing_keys.join("\n\t- ")}"
    end
  end
end
