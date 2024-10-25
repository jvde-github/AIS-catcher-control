# -------------------
# Build Stage for AIS-catcher
# -------------------
FROM debian:bookworm-slim AS build-ais-catcher

RUN apt-get update && apt-get upgrade -y
RUN apt-get install git make gcc g++ cmake pkg-config -y
RUN apt-get install libusb-1.0.0-dev libairspy-dev libhackrf-dev libairspyhf-dev libzmq3-dev libsoxr-dev zlib1g-dev libpq-dev libssl-dev -y

WORKDIR /root/AIS-catcher
COPY . .

RUN git clone https://gitea.osmocom.org/sdr/rtl-sdr.git
RUN cd rtl-sdr && \
    mkdir build && \
    cd build && \
    cmake ../ -DINSTALL_UDEV_RULES=ON -DDETACH_KERNEL_DRIVER=ON && \
    make && make install
RUN cp rtl-sdr/rtl-sdr.rules /etc/udev/rules.d/
RUN ldconfig

RUN git clone https://github.com/ttlappalainen/NMEA2000.git
RUN cd NMEA2000/src && \
    g++ -O3 -c N2kMsg.cpp N2kStream.cpp N2kMessages.cpp N2kTimer.cpp NMEA2000.cpp N2kGroupFunctionDefaultHandlers.cpp N2kGroupFunction.cpp -I. && \
    ar rcs libnmea2000.a *.o

RUN mkdir build && cd build && cmake .. -DNMEA2000_PATH=/root/AIS-catcher/NMEA2000/src && make && make install

# -------------------
# Build Stage for AIS-catcher-control
# -------------------
FROM golang:1.20 AS build-ais-control

WORKDIR /go/src/github.com/jvde-github/AIS-catcher-control
RUN git clone https://github.com/jvde-github/AIS-catcher-control.git .
RUN go build -ldflags="-s -w" -o /go/bin/AIS-catcher-control

# -------------------
# Final Application Container
# -------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get upgrade -y
RUN apt-get install git make gcc g++ cmake pkg-config libusb-1.0-0-dev -y
RUN apt-get install libusb-1.0-0 libairspy0 libhackrf0 libairspyhf1 libzmq5 libsoxr0 libpq5 zlib1g libssl3 -y

RUN cd /root && git clone https://gitea.osmocom.org/sdr/rtl-sdr.git
RUN cd /root/rtl-sdr && \
    mkdir build && \
    cd build && \
    cmake ../ -DCMAKE_BUILD_TYPE=Release -DINSTALL_UDEV_RULES=ON -DDETACH_KERNEL_DRIVER=ON && \
    make && make install
RUN cp /root/rtl-sdr/rtl-sdr.rules /etc/udev/rules.d/
RUN ldconfig

RUN apt-get remove git make gcc g++ cmake pkg-config libusb-1.0-0-dev -y
RUN apt-get autoremove -y

# Copy the AIS-catcher binary from build stage
COPY --from=build-ais-catcher /usr/local/bin/AIS-catcher /usr/local/bin/AIS-catcher

# Copy the AIS-catcher-control binary from build stage
COPY --from=build-ais-control /go/bin/AIS-catcher-control /usr/local/bin/AIS-catcher-control

# Copy the start, restart, is_running, and uptime scripts
COPY start.sh /usr/local/bin/start.sh
COPY restart.sh /usr/local/bin/restart.sh
COPY is_running.sh /usr/local/bin/is_running.sh
COPY uptime.sh /usr/local/bin/uptime.sh
RUN chmod +x /usr/local/bin/*.sh

ENTRYPOINT ["/usr/local/bin/start.sh"]