class Firewall
    def initialize(path)
        #0 is TCP_in, 1 is UDP_in, 2 is TCP_out, 3 is UDP_out
        @rules = Array.new(4) {Array.new(65536)}

        File.foreach(path) do |line|
            rule = line.split(',')
            port = rule[2].split('-')
            ip_address = rule[3].split('-')

            #choose array to add rule in
            rules_index = 0
            if rule[0] === "inbound" 
                rules_index = 1 if rule[1] === "udp"
            else
                rules_index = rule[1] === "tcp" ? 2 : 3
            end

            if port.length() > 1 
                for i in port[0] .. port[1]
                    if rules[rules_index][i].nil?
                        rules[rules_index][i] = Hash.new
                    end
                    if ip_address.length() > 1
                        for j in ip_to_number(ip_address[0]) .. ip_to_number(ip_address[1])
                            rules[rules_index][i][number_to_ip(j)] = true
                        end
                    else
                        rules[rules_index][i][number_to_ip(ip_address[0])] = true
                    end
                end
            else
                if rules[rules_index][port[0]].nil?
                    rules[rules_index][port[0]] = Hash.new
                end
                if ip_address.length() > 1
                    for j in ip_to_number(ip_address[0]) .. ip_to_number(ip_address[1])
                        rules[rules_index][port[0]][number_to_ip(j)] = true
                    end
                else
                    rules[rules_index][port[0]][number_to_ip(ip_address[0])] = true
                end
            end
        end

    end


    def accept_packet(direction, protocol, port, ip_address)
    end

    def ip_to_number(ip_address)
        chunks = ip_address.split('.')
        number = chunks[0].to_s(2) << 24 + chunks[1].to_s(2) << 16 + chunks[2].to_s(2) << 8 + chunks[3].to_s(2)
        number.to_i(2)
    end

    def number_to_ip(ip_number)

    end
end
def ip_to_number(ip_address)
        chunks = ip_address.split('.').map(&:to_i)
        number = (chunks[0] << 24) + (chunks[1] << 16) + (chunks[2] << 8) + chunks[3]
end

def number_to_ip(number)
        chunks = Array.new(4)
        chunks[3] = (255 & number).to_s
        chunks[2] = (((255 << 8) & number) >> 8).to_s
        chunks[1] = (((255 << 16) & number) >> 16).to_s
        chunks[0] = (number >> 24).to_s
        chunks.join(".")
end

puts ip_to_number("192.168.1.1")
puts number_to_ip(ip_to_number("192.168.1.1"))

#fw = Firewall.new("./fw.csv")