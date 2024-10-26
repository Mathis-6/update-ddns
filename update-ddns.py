import httpx
import socket
import time
import json
import os
import sys
import argparse
import traceback
import psutil
import netifaces
import ipaddress
import dns.resolver
from urllib.parse import urlencode, quote
from datetime import datetime
import ipv6


# Console color codes
CCOLORS = {
	"RED": "\033[31m",
	"GREEN": "\033[32m",
	"YELLOW": "\033[33m",
	"CYAN": "\033[36m",
	"RESET": "\033[0m"
}
LOG_TYPES = {
	"ERROR": CCOLORS["RED"],
	"WARNING": CCOLORS["YELLOW"],
	"INFO": CCOLORS["GREEN"],
	"UPDATE": CCOLORS["CYAN"]
}


parser = argparse.ArgumentParser()
parser.add_argument("--config", dest="config_file_path", required=True, type=str)
parser.add_argument("--dry-run", dest="dry_run", action=argparse.BooleanOptionalAction, type=bool, default=False)
parser.add_argument("--debug", dest="debug_mode", action=argparse.BooleanOptionalAction, type=bool, default=False)

args = vars(parser.parse_args())

if not os.path.isfile(args["config_file_path"]):
	print("ERROR: config not found, quitting", file=sys.stderr)
	exit(1)


with open(args["config_file_path"]) as config_file:
	try:
		config = json.loads(config_file.read())

	except json.decoder.JSONDecodeError as error:
		print("ERROR: Badly formatted JSON config", error, file=sys.stderr)
		exit(1)



is_ionos_enabled = "ionos" in config and "zone_id" in config["ionos"]
is_cf_enabled = "cloudflare" in config and "zones" in config["cloudflare"]
is_ipv4_enabled = "remote_ipv4_server_ip" in config and "remote_ipv4_server_port" in config and config["remote_ipv4_server_port"] > 0 and config["remote_ipv4_server_port"] < 65535
is_dry_run = args["dry_run"]
debug = args["debug_mode"]
sudo = "sudo " if os.getuid() != 0 else ""

ionos_http_client = httpx.Client(headers = {
	"X-API-Key": config["ionos"]["api_key"],
	"Content-Type": "application/json",
	"Accept": "application/json"
})

if is_cf_enabled:
	cf_http_client = httpx.Client(headers = {
		"Content-Type": "application/json"
	})


IN_SYSTEMD = psutil.Process(os.getpid()).ppid() == 1


def log_console(message: str, log_type: str = None, log_type_prefix: str = None) -> None:
	
	if log_type in LOG_TYPES:
		if type(log_type_prefix) != str:
			log_type_prefix = log_type
		
		log_type = "[" + LOG_TYPES[log_type] + log_type_prefix + CCOLORS["RESET"] + "] "
	elif type(log_type) is str:
		log_type = f"[{log_type}] "
	else:
		log_type = ""

	if IN_SYSTEMD:	# If running in systemd, timestamps are already shown, don't need to print them
		print(log_type + message)
	else:
		print("[" + datetime.today().strftime("%d/%m %H:%M:%S") + "] " + log_type + str(message))


def update_ipv6_cache_files(ipv6_addr: str|bytes) -> None:
	with open(config["ipv6_prefix_cache_path"], "wb") as file:
		file.write(socket.inet_pton(socket.AF_INET6, ipv6_addr) if type(ipv6_addr) == str else ipv6_addr)
	with open(config["ipv6_mask_cache_path"], "wb") as file:
		file.write(ipv6.get_ipv6_mask(config["ipv6_prefix_length"]))

	log_console("Updated cache files", "INFO")


if is_dry_run:
	log_console("Dry run mode enabled, skipping API updates and writes", "INFO")

if is_ionos_enabled:
	log_console("Testing ionos API...", "INFO")
	response = ionos_http_client.get("https://api.hosting.ionos.com/dns/v1/zones/" + config["ionos"]["zone_id"])
	if response.status_code != 200:
		log_console(f"Bad response code from ionos API when retieving records: {response.status_code}", "ERROR")
		print(response.text)
		exit(1)

	log_console("ionos API tests passed", "INFO")

if is_cf_enabled:
	log_console("Testing Cloudflare API...", "INFO")
	for cf_account_token in config["cloudflare"]["zones"]:
		cf_http_client.headers["Authorization"] = "Bearer " + cf_account_token
		for zone in config["cloudflare"]["zones"][cf_account_token]:
			response = cf_http_client.get(f"https://api.cloudflare.com/client/v4/zones/{zone}")
			if response.status_code != 200:
				log_console(f"Bad response code from Cloudflare API when retieving records for zone {zone}: {response.status_code}", "ERROR")
				print(response.text)
				exit(1)

	log_console("Cloudflare API tests passed", "INFO")


dns_resolver = dns.resolver.Resolver()
dns_resolver.nameservers = config["dns_nameservers"]

if is_ipv4_enabled:
	records = dns_resolver.resolve(config["dns_record_ipv4"], "A")
	for record in records:
		# We need the IPv4 string to be bytes like b'192.0.2.1'
		last_ipv4 = record.address.encode()
		break

records = dns_resolver.resolve(config["dns_record_ipv6"], "AAAA")
for record in records:
	last_ipv6 = record.address
	break	# Take the first IP only

if "last_ipv6" not in locals() or (is_ipv4_enabled and "last_ipv4" not in locals()):
	log_console("Failed to retrieve original DNS records", "ERROR")
	exit(1)


last_ipv6_prefix = ipv6.get_ipv6_prefix(last_ipv6, config["ipv6_prefix_length"], False)
if not is_dry_run:
	update_ipv6_cache_files(last_ipv6_prefix)

log_console(config["dns_record_ipv6"] + ": " + socket.inet_ntop(socket.AF_INET6, last_ipv6_prefix) + "/" + str(config["ipv6_prefix_length"]), "INFO")
if is_ipv4_enabled:
	log_console(config["dns_record_ipv4"] + ": " + last_ipv4.decode(), "INFO")

	ipv4_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	ipv4_socket.bind((config["bind_ipv4"], 0))
	ipv4_socket.settimeout(30)

consecutive_timeouts = 0


while True:
	wan_ipv4 = False
	ipv6_prefix = False
	
	try:
		# If IPv4 is not enabled, wan_ipv4 will always be False, and no other IPv4-related conditions will be executed
		if is_ipv4_enabled:
			# 1 byte of payload + 499 bytes of padding to reach 500 bytes
			# Check https://github.com/Mathis-6/udp-my-ip for more informations
			ipv4_socket.sendto(b"\x01" + (b"\x00" * 499), (config["remote_ipv4_server_ip"], config["remote_ipv4_server_port"]))

			try:
				wan_ipv4 = ipv4_socket.recvfrom(64)[0]
				consecutive_timeouts = 0
			except TimeoutError:
				consecutive_timeouts += 1
				print("timeout #" + str(consecutive_timeouts))
				if (consecutive_timeouts > 60):
					os.system(f"wall '[update-ddns] Reached {consecutive_timeouts} consecutive timeouts when retrieving public IPv4'")

		iface_addrs = netifaces.ifaddresses(config["ipv6_interface"])
		ipv6_addresses = iface_addrs[netifaces.AF_INET6]
		for ip in ipv6_addresses:
			ip = ipaddress.IPv6Address(ip["addr"])

			if ip.is_private or ip.compressed == last_ipv6:
				continue
			
			if ipv6.get_ipv6_prefix(ip.packed, config["ipv6_prefix_length"], False) == last_ipv6_prefix:
				log_console(f"New address with current prefix detected: {ip.compressed}. Doing nothing.", "INFO")
				continue

			print("New IPv6 address detected on " + config["ipv6_interface"] + ": " + ip.compressed + ", deleting the old one " + last_ipv6 + "...")
			command_to_delete_old_address = sudo + "ip -6 address delete " + last_ipv6 + "/64 dev " + config["ipv6_interface"]
			if is_dry_run:
				print(f"Dry-run: Would have executed this command: {command_to_delete_old_address}")
			else:
				os.system(command_to_delete_old_address)
			

			last_ipv6 = ip.compressed
			ipv6_prefix = ipv6.get_ipv6_prefix(ip.packed, config["ipv6_prefix_length"], False)
			break
	
	except:
		log_console(traceback.format_exc(), "ERROR")
		time.sleep(config["retry_delay"])
		continue
	
	if wan_ipv4 == last_ipv4:
		wan_ipv4 = False
	
	if wan_ipv4 == False and ipv6_prefix == False:
		time.sleep(config["update_delay"])
		continue
	
	
	records_list = None
	
	while True:
		
		if ipv6_prefix:
			log_console("New IPv6 GUA prefix detected: " + socket.inet_ntop(socket.AF_INET6, ipv6_prefix) + "/" + str(config["ipv6_prefix_length"]), "UPDATE")
		if wan_ipv4:
			wan_ipv4_str = wan_ipv4.decode()
			log_console(f"New IPv4 detected: {wan_ipv4_str}", "UPDATE")
		
		try:
			response = ionos_http_client.get("https://api.hosting.ionos.com/dns/v1/zones/" + config["ionos"]["zone_id"])
			records_list = json.loads(response.content)
			if "records" not in records_list:
				log_console(f"Unexpected response from ionos API when retrieving zones: {response.text}", "ERROR")
				print(records_list)
				exit(1)
				
			records_list = records_list["records"]
		
		except:
			log_console(traceback.format_exc(), "ERROR")
			time.sleep(config["retry_delay"])
		
		
		try:
			
			cf_query_params = {"match": "any", "type": "AAAA"}

			if wan_ipv4:
				last_ipv4_str = last_ipv4.decode()
				cf_query_params["content"] = last_ipv4_str

			if is_cf_enabled:
				# If any zones are present in the "zones" array, replace the old addresses in these zones
				for cf_account_token in config["cloudflare"]["zones"]:
					# Set the correct account API token in the Authorization header for the next requests
					cf_http_client.headers["Authorization"] = "Bearer " + cf_account_token

					for zone_id in config["cloudflare"]["zones"][cf_account_token]:

						cf_update_payload = {
							"deletes": [],
							"patches": [],
							"puts": [],
							"posts": []
						}
						
						log_console(f"[CLOUDFLARE] Request with zone_id \"{zone_id}\":")
						cf_response = cf_http_client.get("https://api.cloudflare.com/client/v4/zones/" + zone_id + "/dns_records?" + urlencode(cf_query_params, quote_via=quote))
						if cf_response.status_code != 200:
							log_console(f"[CLOUDFLARE] API returned code {cf_response.status_code} when getting records.", "ERROR")
							print(cf_response.text)
							continue
						
						cf_old_records = json.loads(cf_response.content)["result"]
						
						for old_record in cf_old_records:
							# If IPv4 address changed
							if wan_ipv4 and old_record["type"] == "A":
								log_console("[CLOUDFLARE] Updating old IPv4 for " + old_record["name"] + " from " + last_ipv4_str + " to " + wan_ipv4_str, "INFO")

								cf_update_payload["patches"].append({
									"id": old_record["id"],
									"content": wan_ipv4_str
								})


							#	If IPv6 prefix changed								100:: means this is a Worker
							elif ipv6_prefix and old_record["type"] == "AAAA" and (old_record["content"] != "100::") and ipv6.has_ipv6_prefix(old_record["content"], last_ipv6_prefix, config["ipv6_prefix_length"]):
								new_record_ipv6 = ipv6.replace_ipv6_prefix(old_record["content"], ipv6_prefix, config["ipv6_prefix_length"])
								log_console("[CLOUDFLARE] Updating old address  " + old_record["content"] + "  with  " + new_record_ipv6, "INFO")

								cf_update_payload["patches"].append({
									"id": old_record["id"],
									"content": new_record_ipv6
								})

							else:
								if debug:
									log_console("[CLOUDFLARE] Skipping update on record " + old_record["name"] + " with content " + old_record["content"], "DEBUG")
								continue
						
						if len(cf_update_payload["patches"]) > 0:
							if is_dry_run:
								log_console(f"[CLOUDFLARE] Dry run: Would update the following records for {zone_id}:")
								print(cf_update_payload)
							else:
								cf_response = cf_http_client.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/batch", json=cf_update_payload)
								if cf_response.status_code != 200:
									log_console("[CLOUDFLARE] API returned code " + str(cf_response.status_code) + " when getting records")
									print(cf_response.text)
									continue
				

			if is_ionos_enabled:
				patched_records = []

				for i in range(len(records_list)):
					
					# If the record is an A and the content is the old IPv4 address, change it
					if wan_ipv4 and records_list[i]["type"] == "A" and records_list[i]["content"] == last_ipv4_str:
							patched_records.append({"name": records_list[i]["name"], "type": "A", "content": wan_ipv4_str, "ttl": records_list[i]["ttl"], "prio": 0})
					
					# If the record is an AAAA and the content is from the old address
					elif ipv6_prefix and records_list[i]["type"] == "AAAA" and ipv6.has_ipv6_prefix(records_list[i]["content"], last_ipv6_prefix, config["ipv6_prefix_length"]):
						# Then replace the prefix part keeping the host part intact
						new_address = ipv6.replace_ipv6_prefix(records_list[i]["content"], ipv6_prefix, config["ipv6_prefix_length"])
						log_console("[IONOS] Replacing  " + records_list[i]["content"] + "  with  " + new_address, "INFO")
						
						patched_records.append({"name": records_list[i]["name"], "type": "AAAA", "content": new_address, "ttl": records_list[i]["ttl"], "prio": 0})
					
				if len(patched_records):
					if is_dry_run:
						log_console("[IONOS] Dry run: Would update the following records for " + config["ionos"]["zone_id"] + ":", "INFO")
						print(patched_records)
					else:
						response = ionos_http_client.patch("https://api.hosting.ionos.com/dns/v1/zones/" + config["ionos"]["zone_id"], json=patched_records)
						if response.status_code != 200:
							log_console("[IONOS] Bad response code from API: " + str(response.status_code), "ERROR")
							print(response.text)
							exit(1)
					
					print(patched_records)
			
			break
			
		except:
			log_console(traceback.format_exc(), "ERROR")
			time.sleep(config["retry_delay"])
	
	if wan_ipv4:
		last_ipv4 = wan_ipv4
	if ipv6_prefix:
		last_ipv6_prefix = ipv6_prefix
		if not is_dry_run:
			update_ipv6_cache_files(last_ipv6)
	
	time.sleep(config["update_delay"])
