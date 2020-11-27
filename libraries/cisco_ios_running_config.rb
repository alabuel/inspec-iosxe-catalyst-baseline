class CiscoIOSRunningConfig < CiscoIOSBase
  name 'cisco_ios_running_config'

  desc 'Verifies the contents of the running configuration on Cisco IOS devices'

  example <<-EXP
    describe cisco_ios_running_config do
      it { should have_line(/hostname .*/) }
    end
  EXP

  attr_reader :content
  def initialize(section: '', includes: '')
    if section != ''
      @content = ''
      section_found = false
      File.open('output/show_running_config','r') do |f|
        f.each_line do |line|
          if line =~ /^#{section}/ && section_found == false
            section_found = true
          elsif section !~ /^banner/ && line =~ /^\s+.*/ && section_found == true
            @content += line.gsub(/\s+$/, '') + "\n"
          elsif section =~ /^banner/ && line !~ /^banner/ && section_found == true
            @content += line.gsub(/\s+$/, '')
          elsif (line =~ /^banner/ || line =~ /!.*/) && section_found == true
            break
          end
        end
      end
    elsif includes != ''
      @content = ''
      File.open('output/show_running_config','r') do |f|
        f.each_line do |line|
          if line =~ /#{includes}/
            @content += line.gsub(/\s+$/, '') + "\n"
          end
        end
      end
    else
      @content = File.read('output/show_running_config')
    end
  end

  def to_s
    'Cisco IOS Running Config'
  end

  def lines
    @lines ||= parse_running_config(@content).split("\n")
  end

  def has_line?(line) # rubocop:disable PredicateName
    return lines.find { |l| l =~ line } ? true : false if line.is_a?(Regexp)
    lines.include?(line)
  end

  private

  def parse_running_config(content)
    exclamation_point_lines = /!.*\n/
    double_newlines = /\n\n/

    content.gsub(exclamation_point_lines, '')
           .gsub(double_newlines, "\n")
           .gsub(/\s+$/, '')
  end
end
