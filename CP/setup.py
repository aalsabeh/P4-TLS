from ipaddress import ip_address
import sys


p4 = bfrt.basic.pipe

forwarding = p4.Ingress.forwarding
fine_grained = p4.Ingress.fine_grained
coarse_grained = p4.Ingress.coarse_grained

forwarding.clear()
fine_grained.clear()
coarse_grained.clear()


# Forwarding based on IP address
forwarding.add_with_send_using_port(dst_addr=ip_address("10.0.0.1"), port=0)
forwarding.add_with_send_using_port(dst_addr=ip_address("10.0.0.2"), port=1)


# Example 1: Adding a rule to the fine-grained monitoring. Sending "facebook.com" through port 3
# Using CP.py, we can get the P4-based CRC32C hash of facebook.com: 0x74aca149
fine_grained.add_with_send_using_port(servername_hash32="0x74aca149", port=3) 

# Todo: Example 2: Adding a rule to the coarse-grained monitoring. Check Meta4 (DNS parsing P4) github.

bfrt.complete_operations()

# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table forwarding:")
forwarding.dump(table=True)
