control 'SV-234835' do
  title 'The SUSE operating system library directories must have mode 0755 or less permissive.'
  desc 'If the SUSE operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to SUSE operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide shared library directories "/lib", "/lib64", "/usr/lib" and "/usr/lib64" have mode "0755" or less permissive.

Check that the system-wide shared library directories have mode "0755" or less permissive with the following command:

> sudo find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec stat -c "%n %a" '{}' \;

If any of the aforementioned directories are found to be group-writable or world-writable, this is a finding.)
  desc 'fix', "Configure the shared library directories to be protected from unauthorized access. Run the following command:

> sudo find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec chmod 755 '{}' \\;"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-234835'
  tag rid: 'SV-234835r991560_rule'
  tag stig_id: 'SLES-15-010352'
  tag fix_id: 'F-37986r618775_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  mode_for_libs = input('mode_for_libs')

  overly_permissive_libs = input('system_libraries').select { |lib|
    file(lib).more_permissive_than?(mode_for_libs)
  }

  describe 'System libraries' do
    it "should not have modes set higher than #{mode_for_libs}" do
      fail_msg = "Overly permissive system libraries:\n\t- #{overly_permissive_libs.join("\n\t- ")}"
      expect(overly_permissive_libs).to be_empty, fail_msg
    end
  end
end
