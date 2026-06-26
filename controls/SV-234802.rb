control 'SV-234802' do
  title 'Vendor-packaged SUSE operating system security patches and updates must be installed and up to date.'
  desc 'Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep SUSE operating system and application software patched is a common mistake made by IT professionals. New patches are released frequently, and it is often difficult for even experienced System Administrators (SAs) to keep abreast of all the new patches. When new weaknesses in a SUSE operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Verify the SUSE operating system security patches and updates are installed and up to date.

Note: Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO).

Check for required SUSE operating system patches and updates with the following command:

> sudo zypper patch-check

0 patches needed (0 security patches)

If the patch repository data is corrupt, check that the available package security updates have been installed on the system with the following command:

> cut -d "|" -f 1-4 -s --output-delimiter " | " /var/log/zypp/history | grep -v " radd "

2016-12-14 11:59:36 | install | libapparmor1-32bit | 2.8.0-2.4.1
2016-12-14 11:59:36 | install | pam_apparmor | 2.8.0-2.4.1
2016-12-14 11:59:36 | install | pam_apparmor-32bit | 2.8.0-2.4.1

If the SUSE operating system has not been patched within the site or PMO frequency, this is a finding.'
  desc 'fix', 'Install the applicable SUSE operating system patches available from SUSE by running the following command:

> sudo zypper patch'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234802'
  tag rid: 'SV-234802r991589_rule'
  tag stig_id: 'SLES-15-010010'
  tag fix_id: 'F-37953r618676_fix'
  tag cci: ['CCI-000366', 'CCI-001227']
  tag nist: ['CM-6 b', 'SI-2 a']
  tag 'host'
  tag 'container'

  only_if("This control takes a long time to execute so it has been disabled through 'slow_controls'") {
    !input('disable_slow_controls')
  }

  if input('disconnected_system')
    describe 'The system is set to a `disconnected` state and you must validate the state of the system packages manually' do
      skip 'The system is set to a `disconnected` state and you must validate the state of the system packages manually'
    end
  else
    updates = linux_update.updates
    package_names = updates.map { |h| h['name'] }

    describe.one do
      describe 'List of out-of-date packages' do
        subject { package_names }
        it { should be_empty }
      end
      updates.each do |update|
        describe package(update['name']) do
          its('version') { should eq update['version'] }
        end
      end
    end
  end
end
