FROM gcc:latest
WORKDIR /app
COPY src/common /app/common
COPY src/data_user /app/data_user
WORKDIR /app/data_user
RUN make
CMD ["./user"]