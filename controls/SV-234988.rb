control 'SV-234988' do
  title 'The SUSE operating system must disable the x86 Ctrl-Alt-Delete key sequence.'
  desc 'A locally logged-on user, who presses Ctrl-Alt-Delete when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the graphical user interface environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify the SUSE operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

Check that the ctrl-alt-del.target is masked with the following command:

> systemctl status ctrl-alt-del.target
ctrl-alt-del.target
Loaded: masked (/dev/null; maksed)
Active: inactive (dead)

If the ctrl-alt-del.target is not masked, this is a finding.'
  desc 'fix', 'Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the following commands:

> sudo systemctl disable ctrl-alt-del.target

> sudo systemctl mask ctrl-alt-del.target

And reload the daemon to take effect 

> sudo systemctl daemon-reload'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234988'
  tag rid: 'SV-234988r991589_rule'
  tag stig_id: 'SLES-15-040060'
  tag fix_id: 'F-38139r619234_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('user_namespaces_documented') == true
    describe 'User namespaces ISSM approval/documentation' do
      it 'is present' do
        expect(input('user_namespaces_documented')).to eq true
      end
    end
  else
    parameter = 'user.max_user_namespaces'
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
