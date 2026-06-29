control 'SV-234805' do
  title 'The SUSE operating system must display the Standard Mandatory DOD Notice and Consent Banner before granting access via SSH.'
  desc 'Display of a standardized and approved use notification before granting access to the SUSE operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DOD policy. Use the following verbiage for SUSE operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  desc 'check', %q(Verify the SUSE operating system displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via SSH.

Check the issue file to verify it contains one of the DOD required banners. If it does not, this is a finding.

> more /etc/issue

The output must display the following DOD-required banner text:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the output does not display the banner text, this is a finding.

Check for the location of the banner file being used with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*banner'
/etc/ssh/sshd_config.d/80-bannerPointer.conf:Banner /etc/issue

This command will return the banner keyword and the name of the file that contains the SSH banner (in this case "/etc/issue").

If "Banner" is not set to "/etc/issue", this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via ssh.

Edit the "etc/ssh/sshd_config" file or a file in "/etc/ssh/sshd_config.d" to uncomment the banner keyword and configure it to point to a file that will contain the logon banner (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

An example configuration line is:

Banner /etc/issue

Restart the sshd daemon:

> sudo systemctl restart sshd.service

To configure the system logon banner, edit the "/etc/issue" file. Replace the default text inside with the Standard Mandatory DOD banner text:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-234805'
  tag rid: 'SV-234805r1184454_rule'
  tag stig_id: 'SLES-15-010040'
  tag fix_id: 'F-37956r1184453_fix'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 3']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable - SSH is not installed within containerized RHEL', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
  }

  # When Banner is commented, not found, disabled, or the specified file does not exist, this is a finding.
  banner_file = sshd_config.banner

  # Banner property is commented out.
  if banner_file.nil?
    describe 'The SSHD Banner is not set' do
      subject { banner_file.nil? }
      it { should be false }
    end
  end

  # Banner property is set to "none"
  if !banner_file.nil? && !banner_file.match(/none/i).nil?
    describe 'The SSHD Banner is disabled' do
      subject { banner_file.match(/none/i).nil? }
      it { should be true }
    end
  end

  # Banner property provides a path to a file, however, it does not exist.
  if !banner_file.nil? && banner_file.match(/none/i).nil? && !file(banner_file).exist?
    describe 'The SSHD Banner is set, but, the file does not exist' do
      subject { file(banner_file).exist? }
      it { should be true }
    end
  end

  # Banner property provides a path to a file and it exists.
  next unless !banner_file.nil? && banner_file.match(/none/i).nil? && file(banner_file).exist?

  banner = file(banner_file).content.gsub(/[\r\n\s]/, '')
  expected_banner = input('banner_message_text_ral').gsub(/[\r\n\s]/, '')

  describe 'The SSHD Banner' do
    it 'is set to the standard banner and has the correct text' do
      expect(banner).to eq(expected_banner), 'Banner does not match expected text'
    end
  end
end
