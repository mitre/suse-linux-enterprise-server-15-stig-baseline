control 'SV-234832' do
  title 'The SUSE operating system must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.

The /var/log/btmp, /var/log/wtmp, and /var/log/lastlog files have group write and global read permissions to allow for the lastlog function to perform. Limiting the permissions beyond this configuration will result in the failure of functions that rely on the lastlog database.'
  desc 'check', %q(Verify the SUSE operating system has all system log files under the /var/log directory with a permission set to "640", by using the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

> sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;

If command displays any output, this is a finding.)
  desc 'fix', %q(Configure the SUSE operating system to set permissions of all log files under /var/log directory to "640" or more restricted, by using the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

> sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec chmod 640 '{}' \;)
  impact 0.5
  tag check_id: 'C-38020r880882_chk'
  tag severity: 'medium'
  tag gid: 'V-234832'
  tag rid: 'SV-234832r958564_rule'
  tag stig_id: 'SLES-15-010340'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-37983r880883_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  log_file_mode = input('log_file_mode')
  # find's -perm /MASK matches any disallowed bit; the mask is the complement of the max-allowed mode.
  perm_mask = format('%o', 0o777 ^ log_file_mode.to_i(8))
  too_permissive = command("find /var/log -perm /#{perm_mask} ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c '%n %a' {} +").stdout.strip.split("\n").reject(&:empty?)

  describe "Log files under /var/log more permissive than #{log_file_mode} (excluding btmp/wtmp/lastlog)" do
    it 'should not exist' do
      expect(too_permissive).to be_empty, "Log files more permissive than #{log_file_mode}:\n\t- #{too_permissive.join("\n\t- ")}"
    end
  end
end
