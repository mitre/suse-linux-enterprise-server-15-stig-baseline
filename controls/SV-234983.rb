control 'SV-234983' do
  title 'The SUSE operating system must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'The SUSE operating system must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'check', 'Verify the SUSE operating system enforces a delay of at least four seconds between logon prompts following a failed logon attempt.

> grep pam_faildelay /etc/pam.d/common-auth
auth required pam_faildelay.so delay=4000000

If the value of "delay" is not set to "4000000", "delay" is commented out, "delay" is missing, or the "pam_faildelay" line is missing completely, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to enforce a delay of at least four seconds between logon prompts following a failed logon attempt.

Edit the file "/etc/pam.d/common-auth".

Add a parameter "pam_faildelay" and set it to:

> delay is in micro seconds
auth required pam_faildelay.so delay=4000000'
  impact 0.5
  tag check_id: 'C-38171r619218_chk'
  tag severity: 'medium'
  tag gid: 'V-234983'
  tag rid: 'SV-234983r991588_rule'
  tag stig_id: 'SLES-15-040010'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-38134r619219_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'The pam_faildelay configuration in /etc/pam.d/common-auth' do
    subject do
      file('/etc/pam.d/common-auth').content.lines.find do |line|
        line =~ /^\s*auth\s+\S+\s+pam_faildelay\.so/
      end
    end
    it 'must enforce a failed-logon delay of at least 4000000 microseconds (4 seconds)' do
      expect(subject).not_to be_nil, 'No "auth ... pam_faildelay.so" line found in /etc/pam.d/common-auth'
      delay = subject.to_s[/delay=(\d+)/, 1].to_i
      expect(delay).to be >= 4_000_000
    end
  end
end
