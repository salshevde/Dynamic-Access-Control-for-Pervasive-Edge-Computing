FROM gcc:latest
WORKDIR /app
COPY src/common /app/common
COPY src/cloud_server /app/cloud_server
WORKDIR /app/cloud_server
RUN make
CMD ["./server"]
