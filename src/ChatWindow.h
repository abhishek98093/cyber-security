#pragma once
#include <QMainWindow>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTextEdit>
#include <QPushButton>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <memory>
#include <vector>
#include <string>
#include "CryptoUtils.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class ChatWindow : public QMainWindow {
    Q_OBJECT
public:
    ChatWindow(const std::string& configPath, QWidget* parent = nullptr);
    ~ChatWindow();

private slots:
    void onConnectClicked();
    void onDisconnectClicked();
    void onSendClicked();
    void onNewConnection();
    void onReadyRead();
    void onSocketDisconnected();

private:
    void setupUI();
    void appendReceived(const QString& text);
    void processRecvBuffer();
    void sendEncryptedMessage(const QString& message);

    QWidget* central;
    QTextEdit* displayWindow;
    QLineEdit* inputBox;
    QPushButton* connectBtn;
    QPushButton* disconnectBtn;
    QPushButton* sendBtn;

    QTcpServer* server = nullptr;
    QTcpSocket* socket = nullptr;        // active connection
    QByteArray recvBuffer;

    json cfg;
    CryptoUtils crypto;
    size_t aes_key_size;
    size_t aes_block_size = 16; // Hardcoded as AES block size is always 16
};