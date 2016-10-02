#!/usr/bin/env ruby

require 'open-uri'
require './lib/ript_config'

CHAIN="blacklist"

def init
  @fw = RIPTConfig.new(ARGV[0]).conf
  unless (@url = @fw['blacklist_url'])
    puts "no url defined with key \"blacklist_url\". using default url: http://www.openbl.org/lists/base.txt"
    @url = "http://www.openbl.org/lists/base.txt"
  end
  @f4_bin = @fw['iptables_bin']
  @f6_bin = @fw['ip6tables_bin']
  # cleaning current blacklist
  
end

def input_knows_blacklist?
  %x[#{@f4_bin} -n -L INPUT].split(/\n/).each do |line|
    return true if line.match(/^blacklist[\ ].all[\ ].--[\  ].([0].){4}0[\  ].+/)
  end
  false
end

def blacklist_exists?
  %x[#{@f4_bin} -n -L].split(/\n/).each do |line|
    return true if line.match(/^Chain blacklist/)
  end
  false
end

def init_rules
  @f4 = []
  @f4 << "-N #{CHAIN}" unless blacklist_exists?
  @f4 << "-I INPUT -j #{CHAIN}" unless input_knows_blacklist?
  @f4 << "-F #{CHAIN}"
end


def update_chain
  @f4 ||= init_rules
  
  lines = 0
  open(@url) do |io|
    io.read.split(/\n/).each do |line|
      next unless line.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/)
      @f4 << "-A #{CHAIN} -s #{line} -j DROP"
      lines = lines + 1
    end
  end
  puts "found #{lines} ips for black listing"
end

if __FILE__ == $0
  init
  update_chain
  puts "would update system with these rules: "
  @f4.each do |line|
    puts line
    system("#{@f4_bin} #{line}")
  end
end
