# Firewall

## Testing
I didn't have enough to test this implementation thoroughly, so I just used the provided test cases in addition to a few more of my own to see how fast it would be and if it could handle one edge case. 
The edge case I tested was leading 0s in the IP address, which would cause problems since it is technically a correct IP (as far as I know). I handled this by converting the IP to a number and back to standardize the string format.
The large test case I wrote which spans 20k ports and a few thousand IP addresses took a very very long time to load, so this is not a good firewall for very large individual rules. However, I think it can handle large numbers of rules without slowing down too much.

## Design Choices
I chose to store the rules in an array of four arrays, one for each combination of direction and protocol. Each combination had an 65536 sized array so that each port can be looked up in O(1). 
Each port has a Hash that contains the IP addresses that are valid for that port. These choices mean that checking a packet against the rules is generally O(1) time complexity. However, this is definitely a tradeoff against space complexity and startup time.
The startup time if there are large ranges in any rules will be very long, since it iterates over each range of both ports and IPs. This also leads to very high memory usage with large ranges.

I made this choice because I think the number of incoming and outgoing packets will be much higher than the number of times the csv is initially loaded, so this could be a tradeoff worth making.
However, if that is not a desired tradeoff, the code can easily be tweaked to store IP ranges in a list or array for each port, which would dramatically reduce the startup time and memory utilization for large ranges in exchange for a slight increase in lookup time for each packet.

If I had more time I would have thought more about dealing with the combination of large IP ranges and port ranges in the same rule, which my firewall doesn't handle very well right now. I would also add special cases for all IPs and all Ports so that they wouldn't take so much time to load.


# Illumio Team
I'm interested in all three teams, but my preference is the platform team, then the data team, then the policy team. I enjoy learning about and solving complex systems and scaling problems, which is why I think the platform team is the best fit for me. However, I also have some expereince in visualization/graphics which could be helpful in the data team, so I am open to joining any team.
