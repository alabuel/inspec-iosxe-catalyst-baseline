class CiscoIOSInterface < CiscoIOSBase
  name 'cisco_ios_interface'

  desc '
    Cisco IOS Interface Resource
  '

  example <<-EXP
    describe cisco_ios_interface('FastEthernet0/0') do
      its('ip_address') { should eq '10.2.3.2' }
    end
  EXP

  def to_s
    "Cisco IOS Interface #{@name}"
  end

  def initialize(interface_name)
    @name = interface_name
    @info = {}
    @interface = gather_info(interface_name)
    @info[:exist?] = true unless @interface.nil?

    add_methods
  end

  def exist?
    @info[:exist?] == true
  end

  private

  def gather_info(interface_name)
    interfaces = inspec.cisco_ios_interfaces.where(name: interface_name).entries

    if interfaces.length == 1
      interfaces[0]
    elsif interfaces.length > 1
      raise InSpec::Exceptions::ResourceFailed,
            "Interface `#{interface_name}` does not have a unique name " \
            'Please use unique name or the `cisco_ios_interfaces` resource'
    end
  end

  def add_methods
    @interface.to_h.each_pair do |k, v|
      define_singleton_method(k) { v }
    end
  end
end
