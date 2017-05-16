# MacVLan Configuration Script

## Usage

> Please run this script on manager node.

```
usage: mvconf.py [-h] [-f CONF_PATH] [-d] [-r] [-v]

Script to Create MacVLan, Bind Network to each container in Service <For SPD
Bank>

optional arguments:
  -h, --help            show this help message and exit
  -f CONF_PATH, --config-file CONF_PATH
                        config file location, default: ./conf.json
  -d, --disconnect      Disconnect each container in service from network
  -r, --remove-networks
                        Remove networks from each host
  -v, --version         show program's version number and exit

```

## conf.json

```json
{
  "networks": [         // optional, create macvlan network on each node
    {
      "name": "macvlan",
      "subnet": "192.168.8.122/25",
      "gateway": "192.168.8.1",
      "parent": "enp2s0f0.334",
      "ip_range": "192.168.8.122/25"    // optional
    }
  ],
  "services": [
    {
      "name": "2048",
      "network": "macvlan",
      "ip_pool": [                      // optional but recommended
        "192.168.8.136",
        "192.168.8.137-192.168.8.139",
        "192.168.8.139-192.168.8.141"
      ]
    }
  ],
  "auth": {
    "username": "admin",
    "password": "admin"
  }
}
```


