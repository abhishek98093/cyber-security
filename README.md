## 🔐 C18 – Two-Party Secure Messaging App

**C18** is a secure desktop application that enables encrypted messaging between **two peers over LAN**.  
It uses **RSA** for key exchange and **AES** for per-message encryption, with a simple **Qt-based GUI** for communication.  

---

## 🧠 Why C18?  

In today’s world, privacy and confidentiality of communication are crucial.  
Traditional chat systems often lack **end-to-end security**, leaving users exposed to eavesdropping.  

**C18** solves this by:  
- Using **RSA asymmetric cryptography** for secure key exchange  
- Generating a **new AES session key per message**  
- Ensuring that only the intended recipient can decrypt the communication  

This guarantees **confidentiality, integrity, and authenticity** in peer-to-peer messaging.  

---

## ✨ Features  

### 💬 Secure Messaging  
- AES session key generated for **each message**  
- Session key encrypted with receiver’s **RSA public key**  
- Transmitted message = **AES ciphertext + RSA-encrypted session key**  

---

### 🖥️ GUI Elements  
- **Connect Button** → Establish connection with peer  
- **Send Button** → Send encrypted message  
- **Disconnect Button** → Close the session  
- **Input Textbox** → Type your message  
- **Display Window** → Show all received messages (history preserved)  

---

### ⚙️ Configurable Setup  
- All parameters stored in **config.json**:  
  - Peer IP, Ports  
  - Paths to RSA keys  
  - AES key size  

---

## 📦 Dependencies  

```bash
# Update package list
sudo apt update

# Install build tools and dependencies
sudo apt install -y build-essential cmake pkg-config

# Install Qt development libraries (Qt5)
sudo apt install -y qtbase5-dev qt5-qmake qtchooser qttools5-dev-tools libqt5network5

# Install Crypto++ library
sudo apt install -y libcrypto++-dev libcrypto++-utils

# Install OpenSSL (for key generation)
sudo apt install -y openssl

# Install nlohmann-json (header-only library)
sudo apt install -y nlohmann-json3-dev
```  

---

## 📂 Project Setup  

```bash
# Clone the repository
git clone https://github.com/Cyber-Security-July-Dec-2025/C18.git
cd C18

# Create build directory
mkdir build
cd build

# Create keys folder
mkdir keys
cd keys
```  

---

## 🔑 RSA Key Generation  

```bash
# Generate private key (PEM)
openssl genpkey -algorithm RSA -out me_priv.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key (PEM)
openssl rsa -pubout -in me_priv.pem -out me_pub.pem

# Convert private key to DER
openssl pkcs8 -topk8 -inform PEM -outform DER -in me_priv.pem -out me_priv.der -nocrypt

# Convert public key to DER
openssl rsa -in me_priv.pem -pubout -outform DER -out me_pub.der
```  

👉 Share your **me_pub.der** with your peer, and save their public key as **peer_pub.der** in your `keys` folder.  

---

## ⚙️ Configuration  

Create **config.json** inside the `build` folder:  

```json
{
  "aes_key_size": 32,
  "rsa_priv_path": "keys/me_priv.der",
  "rsa_pub_path": "keys/me_pub.der",
  "peer_pub_path": "keys/peer_pub.der",
  "peer_ip": "xx.xx.xx.xx",
  "peer_port": 5001,
  "listen_port": 5000
}
```  

🔧 Replace `xx.xx.xx.xx` with your peer’s IP address and ensure correct port mapping.  

---

## 🛠️ Compilation  

```bash
cd build
cmake ..
make
```  

This generates the executable **SecureChatApp**.  

---

## 🚀 Running the App  

```bash
./SecureChatApp
```  

---

## 💡 Contributions  

We welcome **improvements, feature requests, and bug reports**.  
Help us build a stronger and more secure messaging platform together.
