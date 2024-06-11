

### compile and run this daemon

- build the source code with `go build daemon.go` in this directory  
- copy daemon binary to your server (a virtual machine etc)  
- execute daemon on virtual machine (server) with `./daemon`
- execute daemon (client) with `./daemon --service client --address 192.168.122.100:1099 --localip 10.10.1.2/24`
- try to ping server tun interface from client with `ping 10.10.1.1`


> [!WARNING]  
> this daemon is not suitable for production environment



```console
# ./daemon -h
Usage of ./daemon:
  -address string
    	listen or dial address (default "0.0.0.0:1099")
  -localip string
    	local ip address of tun interface (default "10.10.1.1/24")
  -service string
    	run as server or client (default "server")
```




