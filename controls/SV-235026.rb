control 'SV-235026' do
  title 'The SUSE operating system must not be performing Internet Protocol version 6 (IPv6) packet forwarding by default unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', 'Verify the SUSE operating system is not performing IPv6 packet forwarding by default, unless the system is a router.

Check to see if IPv6 forwarding is disabled by default using the following command:

> sudo sysctl net.ipv6.conf.default.forwarding
net.ipv6.conf.default.forwarding = 0

If the network parameter "ipv6.conf.default.forwarding" is not equal to "0" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to not performing IPv6 packet forwarding by default by running the following command as an administrator:

> sudo sysctl -w net.ipv6.conf.default.forwarding=0

If "0" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "net.ipv6.conf.default.forwarding=0" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  tag check_id: 'C-38214r619347_chk'
  tag severity: 'medium'
  tag gid: 'V-235026'
  tag rid: 'SV-235026r991589_rule'
  tag stig_id: 'SLES-15-040382'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38177r619348_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('packet_forwarding_enabled')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  elsif input('ipv6_enabled') == false
    impact 0.0
    describe 'IPv6 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv6 is disabled on the system, this requirement is Not Applicable.'
    end
  else

    parameter = 'net.ipv6.conf.default.forwarding'
    value = 0
    regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

    describe kernel_parameter(parameter) do
      its('value') { should eq value }
    end

    search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

    correct_result = search_results.any? { |line| line.match(regexp) }
    incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

    describe 'Kernel config files' do
      it "should configure '#{parameter}'" do
        expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
      end
      unless incorrect_results.nil?
        it 'should not have incorrect or conflicting setting(s) in the config files' do
          expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
        end
      end
    end
  end
end
