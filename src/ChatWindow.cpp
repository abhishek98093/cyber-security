#include "ChatWindow.h"
#include <fstream>
#include <iostream>
#include <QHostAddress>
#include <QDataStream>
#include <QMessageBox>

ChatWindow::ChatWindow(const std::string& configPath, QWidget* parent)
    : QMainWindow(parent), crypto()
{
    // Load config
    std::ifstream ifs(configPath);
    if (!ifs) {
        throw std::runtime_error("Cannot open config.json: " + configPath);
    }
    ifs >> cfg;

    aes_key_size = cfg.value("aes_key_size", 32);
    aes_block_size = 16; // AES block size is always 16 bytes

    setupUI();

    // Load keys
    std::string priv = cfg.at("rsa_priv_path").get<std::string>();
    std::string peerpub = cfg.at("peer_pub_path").get<std::string>();

    if (!crypto.LoadPrivateKeyDER(priv)) {
        appendReceived("[ERROR] Load private key failed");
        QMessageBox::critical(this, "Error", "Failed to load private key");
    }
    
    if (!crypto.LoadPeerPublicKeyDER(peerpub)) {
        appendReceived("[ERROR] Load peer public key failed");
        QMessageBox::critical(this, "Error", "Failed to load peer public key");
    }

    // Setup server
    server = new QTcpServer(this);
    QHostAddress listenAddr(QString::fromStdString(cfg.value("listen_ip", "0.0.0.0")));
    quint16 listenPort = cfg.value("listen_port", 5000);
    if (!server->listen(listenAddr, listenPort)) {
        appendReceived(QString("Failed to listen on port %1").arg(listenPort));
        QMessageBox::warning(this, "Warning", "Failed to start server");
    } else {
        appendReceived(QString("Listening on %1:%2").arg(server->serverAddress().toString()).arg(server->serverPort()));
    }
    connect(server, &QTcpServer::newConnection, this, &ChatWindow::onNewConnection);
}

ChatWindow::~ChatWindow() {
    if (socket) { socket->close(); socket->deleteLater(); }
    if (server) { server->close(); server->deleteLater(); }
}

void ChatWindow::setupUI() {
    central = new QWidget(this);
    setCentralWidget(central);
    QVBoxLayout* mainLayout = new QVBoxLayout(central);

    QLabel* status = new QLabel("Two-Party Secure Chat", central);
    mainLayout->addWidget(status);

    displayWindow = new QTextEdit(central);
    displayWindow->setReadOnly(true);
    mainLayout->addWidget(displayWindow, 1);

    inputBox = new QLineEdit(central);
    mainLayout->addWidget(inputBox);

    QHBoxLayout* btnRow = new QHBoxLayout();
    connectBtn = new QPushButton("Connect", central);
    disconnectBtn = new QPushButton("Disconnect", central);
    sendBtn = new QPushButton("Send", central);
    btnRow->addWidget(connectBtn);
    btnRow->addWidget(disconnectBtn);
    btnRow->addWidget(sendBtn);
    mainLayout->addLayout(btnRow);

    connect(connectBtn, &QPushButton::clicked, this, &ChatWindow::onConnectClicked);
    connect(disconnectBtn, &QPushButton::clicked, this, &ChatWindow::onDisconnectClicked);
    connect(sendBtn, &QPushButton::clicked, this, &ChatWindow::onSendClicked);
}

void ChatWindow::appendReceived(const QString& text) {
    displayWindow->append(text);
}

// When another instance connects to our server
void ChatWindow::onNewConnection() {
    // Accept only one connection (simple)
    if (socket) {
        QTcpSocket* extra = server->nextPendingConnection();
        extra->disconnectFromHost();
        extra->close();
        extra->deleteLater();
        appendReceived("Ignored extra incoming connection.");
        return;
    }
    socket = server->nextPendingConnection();
    connect(socket, &QTcpSocket::readyRead, this, &ChatWindow::onReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &ChatWindow::onSocketDisconnected);
    appendReceived(QString("Accepted incoming connection from %1:%2")
                   .arg(socket->peerAddress().toString()).arg(socket->peerPort()));
}

// Connect to peer as client
void ChatWindow::onConnectClicked() {
    if (socket && socket->state() == QAbstractSocket::ConnectedState) {
        appendReceived("Already connected.");
        return;
    }
    socket = new QTcpSocket(this);
    connect(socket, &QTcpSocket::readyRead, this, &ChatWindow::onReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &ChatWindow::onSocketDisconnected);

    QString peerIp = QString::fromStdString(cfg.value("peer_ip", "127.0.0.1"));
    quint16 peerPort = cfg.value("peer_port", 5000);
    appendReceived(QString("Connecting to %1:%2").arg(peerIp).arg(peerPort));
    socket->connectToHost(peerIp, peerPort);
    if (!socket->waitForConnected(3000)) {
        appendReceived("Failed to connect (timeout).");
        socket->deleteLater();
        socket = nullptr;
    } else {
        appendReceived("Connected.");
    }
}

void ChatWindow::onDisconnectClicked() {
    if (!socket) {
        appendReceived("Not connected.");
        return;
    }
    socket->disconnectFromHost();
    socket->waitForDisconnected(1000);
    socket->deleteLater();
    socket = nullptr;
    appendReceived("Disconnected.");
}

void ChatWindow::onSocketDisconnected() {
    appendReceived("Peer disconnected.");
    if (socket) {
        socket->deleteLater();
        socket = nullptr;
    }
}

// Read incoming bytes and buffer until a full message can be parsed
void ChatWindow::onReadyRead() {
    if (!socket) return;
    recvBuffer.append(socket->readAll());
    processRecvBuffer();
}

void ChatWindow::processRecvBuffer() {
    QDataStream ds(recvBuffer);
    ds.setByteOrder(QDataStream::BigEndian);
    
    while (!ds.atEnd()) {
        // Try to read a complete message
        quint32 n_iv, n_encKey, n_cipher;
        
        // Check if we have enough data for the headers
        if (recvBuffer.size() < static_cast<int>(ds.device()->pos() + sizeof(quint32) * 3)) {
            break;
        }
        
        // Store current position in case we need to roll back
        qint64 startPos = ds.device()->pos();
        
        // Read lengths
        ds >> n_iv;
        if (recvBuffer.size() < static_cast<int>(ds.device()->pos() + n_iv + sizeof(quint32) * 2)) {
            // Not enough data, reset position and wait for more
            ds.device()->seek(startPos);
            break;
        }
        
        // Read IV
        QByteArray iv;
        iv.resize(n_iv);
        ds.readRawData(iv.data(), n_iv);
        
        // Read encrypted key length
        ds >> n_encKey;
        if (recvBuffer.size() < static_cast<int>(ds.device()->pos() + n_encKey + sizeof(quint32))) {
            ds.device()->seek(startPos);
            break;
        }
        
        // Read encrypted key
        QByteArray encKey;
        encKey.resize(n_encKey);
        ds.readRawData(encKey.data(), n_encKey);
        
        // Read ciphertext length
        ds >> n_cipher;
        if (recvBuffer.size() < static_cast<int>(ds.device()->pos() + n_cipher)) {
            ds.device()->seek(startPos);
            break;
        }
        
        // Read ciphertext
        QByteArray cipher;
        cipher.resize(n_cipher);
        ds.readRawData(cipher.data(), n_cipher);
        
        // Convert to vectors
        std::vector<unsigned char> v_iv(iv.begin(), iv.end());
        std::vector<unsigned char> v_encKey(encKey.begin(), encKey.end());
        std::vector<unsigned char> v_cipher(cipher.begin(), cipher.end());

        // Decrypt AES key with our private key
        std::vector<unsigned char> aesKey = crypto.RSADecryptWithPrivate(v_encKey);
        if (aesKey.empty()) {
            appendReceived("[ERROR] Failed to decrypt session key");
            continue;
        }
        
        // AES decrypt
        std::string plain = crypto.AESDecrypt(aesKey, v_iv, v_cipher);
        appendReceived(QString("[Peer] %1").arg(QString::fromStdString(plain)));
        
        // Remove processed data from buffer
        recvBuffer = recvBuffer.mid(ds.device()->pos());
        ds.device()->seek(0); // Reset stream to beginning of remaining data
    }
}

void ChatWindow::onSendClicked() {
    QString text = inputBox->text();
    if (text.isEmpty()) return;
    if (!socket || socket->state() != QAbstractSocket::ConnectedState) {
        appendReceived("Not connected. Press Connect first.");
        return;
    }
    sendEncryptedMessage(text);
    inputBox->clear();
}

void ChatWindow::sendEncryptedMessage(const QString& message) {
    // Generate AES key + IV
    std::vector<unsigned char> aesKey = crypto.GenerateRandomBytes(aes_key_size);
    std::vector<unsigned char> iv = crypto.GenerateRandomBytes(aes_block_size);

    // AES encrypt message
    std::vector<unsigned char> cipher = crypto.AESEncrypt(aesKey, iv, message.toStdString());
    if (cipher.empty()) {
        appendReceived("[ERROR] AES encryption failed");
        return;
    }

    // RSA encrypt AES key with peer public key
    std::vector<unsigned char> encKey = crypto.RSAEncryptWithPeerPublic(aesKey);
    if (encKey.empty()) {
        appendReceived("[ERROR] RSA encryption failed (check peer public key)");
        return;
    }

    // Build packet
    QByteArray packet;
    QDataStream ds(&packet, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::BigEndian);
    
    // Write IV
    ds << static_cast<quint32>(iv.size());
    ds.writeRawData(reinterpret_cast<const char*>(iv.data()), iv.size());
    
    // Write encrypted key
    ds << static_cast<quint32>(encKey.size());
    ds.writeRawData(reinterpret_cast<const char*>(encKey.data()), encKey.size());
    
    // Write ciphertext
    ds << static_cast<quint32>(cipher.size());
    ds.writeRawData(reinterpret_cast<const char*>(cipher.data()), cipher.size());

    qint64 written = socket->write(packet);
    if (written == -1) {
        appendReceived("[ERROR] Failed to write to socket");
    } else {
        appendReceived(QString("[Me] %1").arg(message));
    }
}