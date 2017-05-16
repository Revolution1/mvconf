# MacVLan Configuration Script

## Usage

> Please run this script on manager node.

```
usage: mvconf [-h] [-f CONF_PATH] [-v]

Script to Create MacVLan, Bind Network to Service <For SPD Bank>

optional arguments:
  -h, --help            show this help message and exit
  -f CONF_PATH, --config-file CONF_PATH
                        config file location, default: ./conf.json
  -v, --version         show program's version number and exit
```

## conf.json

```
{
  "networks": [
    {
      "name": "test",
      "subnet": "192.168.8.122/25",
      "gateway": "192.168.8.1",
      "ip_range": "192.168.8.122/25" // optional
    }
  ],
  "services": [
    {
      "name": "2048",
      "network": "test",
      "ip": "192.168.8.137" // optional
    }
  ],
  "auth": {
    "username": "admin",
    "password": "admin"
  }
}
```


