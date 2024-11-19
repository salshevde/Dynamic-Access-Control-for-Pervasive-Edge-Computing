FROM gcc:latest
WORKDIR /app
COPY src/common /app/common
COPY src/data_owner /app/data_owner
WORKDIR /app/data_owner
RUN make
CMD ["./owner"]