# Dynamic-Access-Control-for-Pervasive-Edge-Computing

### Cloud Server

1. Navigate to the `cloud-server` source directory:
   ```bash
   cd src/cloud-server
   ```

2. Compile the cloud storage server:
   ```bash
   gcc -o cloud-storage-server cloud-storage-server.c -lsqlite3 -lpthread
   ```

3. Run the cloud storage server:
   ```bash
   ./cloud-storage-server
   ```

---

### Data Owner

1. Navigate to the `data-owner` source directory:
   ```bash
   cd src/data-owner
   ```

2. Compile the data owner application:
   ```bash
   cc data-owner.c ../common/crypto.c ../common/cJSON.c ../common/fileutils.c -o owner -lsqlite3 -lpbc -lssl -lcrypto -lgmp -lpari
   ```

3. Run the data owner application:
   ```bash
   ./owner
   ```

---

### Data User

1. Navigate to the `data-user` source directory:
   ```bash
   cd src/data-user
   ```

2. Compile the data user application:
   ```bash
   gcc data-user.c -o user ../common/crypto.c ../common/cJSON.c ../common/fileutils.c -lsqlite3 -lpbc -lssl -lcrypto -lgmp -lpari
   ```

3. Run the data user application:
   ```bash
   ./user
   ```
```