# pico_tcp_multicore_server
Pi Pico W TCP server

Networking project for learning how to use the pico w for future IoT projects. 

Blink code to pin 19 running on core 0.

core 1 connects to WiFi and sets up at TCP server. Listens for incoming TCP connections which can blink onboard cyw43 controlled LED. Can be done with for example Telnet. 

Setup:
* Setup pico sdk and toolchain: https://datasheets.raspberrypi.com/pico/getting-started-with-pico.pdf
* run cmake with:  ```cmake -DPICO_BOARD=pico_w ..``` in build folder
* Create ```secrets.h``` and define ```WIFI_SSID``` and ```WIFI_PASSWORD```
* run ```make``` in build folder
