class CiscoIOSSnmpGroups < CiscoIOSBase
  name 'cisco_ios_snmp_groups'

  desc '
    Cisco IOS SNMP Groups Resource
  '

  example <<-EXP
    describe cisco_ios_snmp_groups.where { security_model !~ /v3 priv/ } do
      its('entries') { should be_empty }
    end
  EXP

  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:access_list, field: :access_list)
        .add(:name, field: :name)
        .add(:notifyview, field: :notifyview)
        .add(:readview, field: :readview)
        .add(:row_status, field: :row_status)
        .add(:security_model, field: :security_model)
        .add(:writeview, field: :writeview)

  filter.connect(self, :params)

  def to_s
    'Cisco IOS SNMP Groups'
  end

  def enabled?
    @enabled ||= File.read('output/show_snmp') != '%SNMP agent not enabled'
  end

  def params
    return nil unless enabled?
    
    parse_snmp_groups(File.read('output/show_snmp_group'))
  end

  private

  def parse_snmp_groups(output)
    raw_groups = output.split("\n\n")

    groups = []
    raw_groups.each do |raw_group|
      groups.push(translate_raw_group(raw_group))
    end
    groups
  end

  def translate_raw_group(raw_group)
    group = {}

    split_raw_group(raw_group).each do |k, v|
      v = nil if v =~ /<no.*specified>/
      group[k.to_sym] = v
    end

    group
  end

  def split_raw_group(raw_group)
    parsed = []

    parsed.push(slice_group!(raw_group, /groupname:.*  /))
    parsed[-1][0] = 'name'

    parsed.push(slice_group!(raw_group, /security model:.*\n/))
    parsed[-1][0] = 'security_model'

    parsed.push(slice_group!(raw_group, /readview : .* writeview:/))
    parsed[-1][1] = parsed[-1][1].slice(/.*   /).strip

    parsed.push(slice_group!(raw_group, /.*\n/))
    parsed[-1] = ['writeview', parsed[-1][0]]

    parsed.push(slice_group!(raw_group, /notifyview:.*/))

    if raw_group =~ /access-list/
      parsed.push(slice_group!(raw_group, /row status.*\t/))
      parsed[-1][0] = 'row_status'

      parsed.push(slice_group!(raw_group, /access-list:.*/))
      parsed[-1][0] = 'access_list'
    else
      parsed.push(slice_group!(raw_group, /row status.*/))
      parsed[-1][0] = 'row_status'
    end

    parsed
  end

  def slice_group!(group, regex)
    group.slice!(regex).split(':').map(&:strip)
  end
end
