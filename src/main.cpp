#include <QApplication>
#include "ChatWindow.h"
#include <iostream>

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    std::string cfg = "config.json";
    if (argc > 1) cfg = argv[1];
    
    try {
        ChatWindow w(cfg);
        w.resize(700, 500);
        w.show();
        return a.exec();
    } catch (const std::exception& e) {
        std::cerr << "Failed to start application: " << e.what() << std::endl;
        return 1;
    }
}