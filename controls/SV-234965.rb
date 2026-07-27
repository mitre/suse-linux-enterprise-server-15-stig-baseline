control 'SV-234965' do
  title 'The SUSE operating system must allocate audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.'
  desc 'To ensure SUSE operating systems have a sufficient storage capacity in which to write the audit logs, SUSE operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the SUSE operating system.'
  desc 'check', 'Verify the SUSE operating system allocates audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.

Determine to which partition the audit records are being written with the following command:

> sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to (with the example being /var/log/audit/) with the following command:

> df -h /var/log/audit/
/dev/sda2 24G 10.4G 13.6G 43% /var

If the audit records are not written to a partition made specifically for audit records (/var/log/audit is a separate partition), determine the amount of space being used by other files in the partition with the following command:

> sudo du -sh [audit_partition]
1.8G /var/log/audit

The partition size needed to capture a week of audit records is based on the activity level of the system and the total storage capacity available. In normal circumstances, 10.0 GB of storage space for audit records will be sufficient.

If the audit record partition is not allocated sufficient storage capacity, this is a finding.'
  desc 'fix', 'Allocate enough storage capacity for at least one week of SUSE operating system audit records when audit records are not immediately sent to a central audit record storage facility.

If audit records are stored on a partition made specifically for audit records, use the "YaST2 - Partitioner" program (installation and configuration tool for Linux) to resize the partition with sufficient space to contain one week of audit records.

If audit records are not stored on a partition made specifically for audit records, a new partition with sufficient amount of space will need be to be created. The new partition can be created using the "YaST2 - Partitioner" program on the system.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-234965'
  tag rid: 'SV-234965r958752_rule'
  tag stig_id: 'SLES-15-030660'
  tag fix_id: 'F-38116r619165_fix'
  tag cci: ['CCI-001849', 'CCI-001851']
  tag nist: ['AU-4', 'AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_log_dir = command("dirname #{auditd_conf.log_file}").stdout.strip

  describe file(audit_log_dir) do
    it { should exist }
    it { should be_directory }
  end

  # Fetch partition sizes in 1K blocks for consistency
  partition_info = command("df -B 1K #{audit_log_dir}").stdout.split("\n")
  partition_sz_arr = partition_info.last.gsub(/\s+/m, ' ').strip.split

  # Get unused space percentage
  percentage_space_unused = (100 - partition_sz_arr[4].to_i)

  describe "auditd_conf's space_left threshold" do
    it 'should be under the amount of space currently available (in 1K blocks) for the audit log directory' do
      expect(auditd_conf.space_left.to_i).to be <= percentage_space_unused
    end
  end
end
