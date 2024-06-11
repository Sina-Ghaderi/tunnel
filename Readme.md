# Tunnel

Tunnel is a golang [tun](https://www.kernel.org/doc/Documentation/networking/tuntap.txt) package that supports
generic segment/receive offloads ([gso](https://docs.kernel.org/networking/segmentation-offloads.html#generic-segmentation-offload) and [gro](https://docs.kernel.org/networking/segmentation-offloads.html#generic-receive-offload)) in linux.  


- supports gso and gro for both udp* and tcp
- data gets reassembled when user does not provide hole ipv4 or ipv6 packet in one write method call
- reduce number of read/write syscalls when gso/gro is enabled


> Tunnel udp offloading was added in linux v6.2, for prior versions udp offloading is disabled  
> This package does not implement tap device

### How does gso/gro improve performance?

The linux tun/tap driver is designed to process one packet at a time for each read and write syscall. This means that with each write or read syscall, a single packet, sized according to the tunnel's MTU (maximum transmission unit), is written or read. Considering that system calls are relatively expensive operations, this approach negatively impacts the performance and throughput of the tunnel.  
By using generic segmentation and receive offloads and setting the IFF_VNET_HDR flag (virtual network header), more than one packet can be written to or read from the tunnel file descriptor in each read and write operation.  

<p align="center">
   <img src="https://github.com/sina-ghaderi/tunnel/blob/master/diagram.jpg" alt="diagram"/>
</p>

This reduces the number of system calls required and consequently improves performance and throughput by allowing larger data chunks to be processed in a single syscall operation.

### How to use this package: A simple VPN service

For sake of simplicity, in the source code below, setting the IP address on the tunnel interface is done using the ip command. However, for a production environment, it's recommended to use the kernel's netlink APIs directly.

```go
// request new tun device from kernel
device, err := tunnel.New(tunnel.Config{})
if err != nil {
	panic(err)
}

// setting ip by using ip command 
ipa := "192.168.87.1/24"
cmd := exec.Command("/usr/bin/ip", "addr", "add", ipa, "dev", device.Name())
if err := cmd.Run(); err!= nil {
    panic(err)
}

// setting interface up
cmd := exec.Command("/usr/bin/ip", "link", "set", device.Name(), "up")
if err := cmd.Run(); err!= nil {
    panic(err)
}

// conn can be any type of ReadWriteCloser, typically a network connection  
conn := someIoReadWriteCloser() 

var wg sync.WaitGroup
wg.Add(2)

// read from conn and write to tun device
go func() {
	defer device.Close()
	io.Copy(device, conn)
	wg.Done()
}()

// read from tun device and write to conn
go func() {
	defer conn.Close()
	io.Copy(conn, device)
	wg.Done()
}()

wg.Wait()

```

Checkout the [_example](_example) for a simple vpn over tcp daemon (not suitable for production environment)


### Tunnel Configuration Structure
The tunnel configuration structure includes the following fields:
```go
type Config struct {
	Name          string             // Name of the tunnel interface (e.g., "tun0")
	Persist       bool               // Whether the tunnel interface should persist (remain after being closed)
	Permissions   *DevicePermissions // Permissions for the tunnel device
	MultiQueue    bool               // Whether to enable multi-queue support
	DisableGsoGro bool               // Whether to disable gso/gro and VnetHDR
}
```

**Persist:** Indicates whether the tunnel interface should persist. If set to true, the interface will remain active even after being closed.  
**Permissions:** A pointer to a DevicePermissions structure that defines the permissions for the tunnel device. This can include read/write permissions and any other access control settings.  
```go
type DevicePermissions struct {
    Owner uint   // UID of the owner
    Group uint   // GID of the group
}
```

**MultiQueue:** Enables or disables multiqueue support, which can improve performance by allowing multiple queues for packet processing.  
Following is the Linux MultiQueue documentation:

> From version 3.8, Linux supports multiqueue tuntap which can uses multiple  
> file descriptors (queues) to parallelize packets sending or receiving. The  
> device allocation is the same as before, and if user wants to create multiple  
> queues, TUNSETIFF with the same device name must be called many times with  
> IFF_MULTI_QUEUE flag.  
> 
> char *dev should be the name of the device, queues is the number of queues to  
> be created, fds is used to store and return the file descriptors (queues)  
> created to the caller. Each file descriptor were served as the interface of a  
> queue which could be accessed by userspace.  


**DisableGsoGro:** Indicates whether to disable gso/gro and VnetHDR



### contribute to this project
feel free to email me sina@snix.ir if you want to contribute to this project

Copyright 2024 SNIX LLC sina@snix.ir
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License version 2 as published by the Free Software Foundation.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.