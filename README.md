# update-ddns

This program checks for IPv6/v4 addresses changes, and updates the linked domains accordingly.
<br>
You don't need to install a separate DDNS client on each of your IPv6 machines anymore.

## Getting started

Start by cloning the repository:

```shell
git clone https://github.com/Mathis-6/update-ddns.git
```

Move the config.json outside of the repository to prevent git pulls overwriting the config
<br>

Install the dependencies:

```shell
pip install -r requirements.txt
```

## Configuring

All the configuration is stored in config.json
<br>
Change the values depending on your environment.

`update_delay`: The interval between IP checks.

`retry_delay`: Wait n seconds after a fail.

`dns_nameservers`: List of DNS resolvers used to resolve `dns_record_ipv4` and `dns_record_ipv6` at startup.

`ipv6_prefix_length`: The prefix length, delegated by the ISP. Generally this is 56, but can be 48 in some ISP.

`ipv6_interface`: The local interface on which the IP checks will be made.<br>
The is generally an ethernet interface connected to the local network.

`dns_record_ipv6`: The DNS record that we will check the IP against.<br>
If the current IP is different, this will trigger a DNS update.


### The following are optional:

`remote_ipv4_server_ip`: IP address of the remote UDP server returning the client IPv4 address.<br>
See https://github.com/Mathis-6/udp-my-ip

`remote_ipv4_server_port`: Port for `remote_ipv4_server_ip`.

`bind_ipv4`: The IPv4 address to bind to when sending packets to `remote_ipv4_server_ip`.

`ipv6_prefix_cache_path`: OPTIONAL: Writes the 16-bytes IPv6 prefix in this file.<br>
Can be used by other applications to determine the local network.

`ipv6_mask_cache_path`: OPTIONAL: The 16-bytes mask obtained by `ipv6_prefix_length` will be written to this file.<br>
Can be used by other applications.

`dns_record_ipv4`: Same thing as `dns_record_ipv6`, but optional.

`shell_commands`: List of commands to execute after the IPv6 prefix has changed.

`ionos`.`zone_id`: Your DNS zone ID.<br>
`ionos`.`api_key`: The account API key.

`cloudflare`.`zones`: The list of zones to update in the form of<br>
`account api key`: [list of Zone IDs to update]

The account API key can be obtained in your Cloudflare dashboard:<br>
My Profile > API Tokens > Create token > Edit zone DNS (Use template)<br>
In *Zone Resources* select *include All zones* then click **Continue**

To add a zone, click on a domain you added in your dashboard.<br>
On the bottom right, you will see a **Zone ID**
Copy the value and add it to the config.

If you don't use some settings, simply remove them from the config.json file.

## Running the service

Create a service file as follow:

```shell
nano /etc/systemd/system/update-ddns.service
```

And paste this content

```
[Unit]
Description=Automatically update domains with dynamic IPv6/v4
After=multi-user.target

[Service]
Type=simple
Restart=no
ExecStart=/usr/bin/python3 -u /path/to/update-ddns.py --config /path/to/config.json

[Install]
WantedBy=multi-user.target
```

Update-ddns use the `ip` shell command to delete the old IP address after an IPv6 update.<br>
If the service is not run as root, you will need to give the user a sudo access to the `ip` command without password.
