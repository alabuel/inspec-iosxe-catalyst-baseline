class CiscoIOSSnmpUsers < CiscoIOSBase
  name 'cisco_ios_snmp_users'

  desc '
    Cisco IOS SNMP Users Resource
  '

  example <<-EXP
    describe cisco_ios_snmp_users.where { privacy_protocol == 'MD5' } do
      its('entries') { should be_empty }
    end
  EXP

  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:authentication_protocol, field: :authentication_protocol)
        .add(:group_name, field: :group_name)
        .add(:name, field: :name)
        .add(:privacy_protocol, field: :privacy_protocol)
        .add(:storage_type, field: :storage_type)
        .add(:version, field: :version)

  filter.connect(self, :params)

  def to_s
    'Cisco IOS SNMP Users'
  end

  def params
    params = []

    gather_users_from_running_config.each { |user| params.push(user) }
    gather_users_from_show_snmp_user.each { |user| params.push(user) }

    params
  end

  private

  def gather_users_from_running_config
    users = []

    output = ''
    File.read("output/show_running_config") do |f|
      f.each_line do |line|
        if line =~ /snmp-server user/
          output += line.gsub(/\s+$/, '') + "\n"
        end
      end
    end
    output.split("\n").each do |line|
      info = line.split(' ')
      users.push(
        authentication_protocol: nil,
        storage_type: nil,
        privacy_protocol: nil,
        name: info[2],
        group_name: info[3],
        version: info[4] == 'v1' ? '1' : '2'
      )
    end

    users
  end

  def gather_users_from_show_snmp_user
    users = []

    raw_users = File.read('output/show_snmp_user').split("\n\n")

    raw_users.each { |x| users.push(parse_raw_user(x)) }

    users
  end

  def parse_raw_user(raw_user)
    user = {}

    user[:version] = '3'

    raw_user.split("\n").reject(&:empty?).each do |line|
      k, v = line.split(':').map(&:strip)
      case k
      when /Authentication Protocol/
        user[:authentication_protocol] = v
      when /Group-name/
        user[:group_name] = v
      when /Privacy Protocol/
        user[:privacy_protocol] = v == 'None' ? nil : v
      when /storage-type/
        user[:storage_type] = v.split("\t").map(&:strip)
      when /User name/
        user[:name] = v
      end
    end

    user
  end
end
