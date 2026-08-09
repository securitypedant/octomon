# Octomon - Monitor your overall network performance
Nothing is worse than not knowing what your network performance is like. Sitting on plane, 
airport wifi, or just ta home and wondering what's going on.

This tool is designed to give you a simple view of your network connectivity in the command line.

## Prompt to build this.
A CLI tool for macos and linux that gives the user a dashboard like view of network performance.

Think btop, trippy and bandwhich in a single tool. I want to be able to do the following.

1. Understand the current quality of my network connection as determined by ICMP requests showing jitter, packet loss and overall latency to a range of default known endpoints (1.1.1.1, 8.8.8.8) as well as user configurable targets.
2. View graphs of the current bandwidth capabilities as well as what processes are using my current bandwidth. So imagine a periodic down/up speed test to get some limits, then show what processes are currently using bandwidth.
3. What my network is. DHCP/IP etc details. Transport info, Wifi? 10/100/1000Mb connection?
4. A minor view on machine performance. So CPU/memory usage graphs, but only to give me an idea of if my machine performance is possibly impacting network performance.
