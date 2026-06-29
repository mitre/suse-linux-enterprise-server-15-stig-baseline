control 'SV-234827' do
  title 'The SUSE operating system SSH daemon must be configured with a timeout interval.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the SUSE operating system-level, and deallocating networking assignments at the application level if multiple application sessions are using a single SUSE operating system-level network connection. This does not mean that the SUSE operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', %q(Verify the SUSE operating system SSH daemon is configured to timeout idle sessions.

Check that the "ClientAliveInterval" parameter is set to a value of "600" with the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*clientaliveinterval'

ClientAliveInterval 600

If "ClientAliveInterval" is not set to "600" in "/etc/ssh/sshd_config", this is a finding.)
  desc 'fix', 'Configure the SUSE operating system SSH daemon to timeout idle sessions.

Add or modify (to match exactly) the following line in the "/etc/ssh/sshd_config" file:

ClientAliveInterval 600

The SSH daemon must be restarted for any changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000126-GPOS-00066', 'SRG-OS-000279-GPOS-00109', 'SRG-OS-000395-GPOS-00175']
  tag gid: 'V-234827'
  tag rid: 'SV-234827r986464_rule'
  tag stig_id: 'SLES-15-010280'
  tag fix_id: 'F-37978r618751_fix'
  tag cci: ['CCI-001133', 'CCI-000879', 'CCI-002361', 'CCI-002891']
  tag nist: ['SC-10', 'MA-4 e', 'AC-12', 'MA-4 (7)']
  tag 'host'
  tag 'container-conditional'

  setting = 'ClientAliveInterval'
  gssapi_authentication = input('sshd_config_values')
  value = gssapi_authentication[setting]
  openssh_present = package('openssh-server').installed?

  only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || openssh_present
  }

  if input('allow_container_openssh_server') == false
    describe 'In a container Environment' do
      it 'the OpenSSH Server should be installed only when allowed in a container environment' do
        expect(openssh_present).to eq(false), 'OpenSSH Server is installed but not approved for the container environment'
      end
    end
  else
    describe 'The OpenSSH Server configuration' do
      it "has the correct #{setting} configuration" do
        expect(sshd_config.params[setting.downcase]).to cmp(value), "The #{setting} setting in the SSHD config is not correct. Ensure it is set to '#{value}'."
      end

      it "has the correct #{setting} runtime value" do
        runtime_value = command('sshd -T').stdout.match(/^#{setting.downcase}\s+(\S+)/i)&.captures&.first
        expect(runtime_value).to cmp(value), "The #{setting} runtime value is not correct. Ensure sshd -T resolves '#{setting}' to '#{value}'."
      end
    end
  end
end
