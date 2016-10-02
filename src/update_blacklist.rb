#!/usr/bin/env ruby

require 'open-uri'
require_relative './lib/ript_config'

CHAIN="blacklist"

def init
  @fw = RIPTConfig.new(ARGV[0])
  unless (@url = @fw.conf['blacklist_url'])
    puts "no url defined with key \"blacklist_url\". using default url: http://www.openbl.org/lists/base.txt"
    @url = "http://www.openbl.org/lists/base.txt"
  end
end

def input_knows_blacklist?
  %x[#{@fw.f4_bin} -n -L INPUT].split(/\n/).each do |line|
    return true if line.match(/^blacklist[\ ].all[\ ].--[\  ].([0].){4}0[\  ].+/)
  end
  false
end

def blacklist_exists?
  %x[#{@fw.f4_bin} -n -L].split(/\n/).each do |line|
    return true if line.match(/^Chain blacklist/)
  end
  false
end

def update_chain
  yield "-N #{CHAIN}" unless blacklist_exists?
  yield "-I INPUT -j #{CHAIN}" unless input_knows_blacklist?
  yield "-F #{CHAIN}"
  open(@url) do |io|
    io.read.split(/\n/).each do |line|
      next unless line.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/)
      yield "-A #{CHAIN} -s #{line} -j DROP"
    end
  end
end

if __FILE__ == $0
  init
  update_chain do |line|
    system("#{@fw.f4_bin} #{line}")
  end
end
