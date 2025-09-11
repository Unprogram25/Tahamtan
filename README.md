Serial & TCP Communication GUI 🔌

This is a professional and versatile GUI application designed to simplify serial and TCP communications. Developed in Python using the tkinter library, this tool allows you to easily connect, send, and receive data from various devices and servers, providing a clear and efficient way to manage your communication links.

Features ✨

Clean and Intuitive UI: Built with tkinter for a responsive and user-friendly experience.

Multi-Protocol Support:

Serial: Scans for available serial ports, automatically saves the last-used settings (Port and Baud Rate), and manages connections.

TCP Client: Connects to TCP servers, sends/receives data, and includes a built-in ping utility to measure Round-Trip Time (RTT).

TCP Server: Starts a TCP server on a specified port to listen for and handle incoming client connections.

Visual Status Indicators: Uses color-coded status lights to provide a quick visual overview of the connection state (disconnected, connecting, or connected).

Multi-threaded Operations: All communication and network tasks are handled in separate threads to prevent the GUI from freezing.

Preset Commands: A dropdown menu allows for quick sending of predefined commands to the connected device.

End-of-Line (EOL) Options: Offers a choice between \r\n, \n, \r, and None for message termination.

Configuration Management: Automatically saves and loads your last-used port and baud rate settings to a config.json file.

Installation and Setup 🚀

To run this application, you need Python 3 and the following libraries. You can install them using pip:

Bash

pip install pyserial
pip install ping3
How to Run
After installing the dependencies, simply execute the main script:

Bash

python main.py

Usage 🖥️

Serial Tab
Port: Select your device's serial port from the dropdown. Use the Refresh button to update the list of available ports.

Baud Rate: Choose the desired baud rate for communication.

Connect/Disconnect: Click the button to establish or terminate the serial connection.

TCP Client Tab

IP Address and Port: Enter the IP address and port of the target TCP server.

Connect/Disconnect: Use this button to connect to the server.

Ping: Click to measure the Round-Trip Time (RTT) to the destination IP address.

TCP Server Tab

Port: Specify the port on which you want the server to listen.

Listen: Click this button to start the TCP server and accept incoming client connections.

Messages sent and received will be displayed in the console window at the bottom of the application.

Code Structure 🏗️

The project is organized using an object-oriented and modular approach for clarity and maintainability.

main.py: The core file that initializes the main GUI application.

SerialManager: A class encapsulating all logic and GUI elements for serial communication.

TcpClientManager: A class that manages the TCP client functionality.

TcpServerManager: A class dedicated to handling the TCP server logic.

ConfigurationManager: A utility class for saving and loading application settings.

helper_functions: A collection of reusable functions for drawing shapes and updating visual indicators.

Contributing 🤝

Contributions are welcome! If you have suggestions for new features, bug fixes, or performance improvements, please feel free to create a pull request.

License 📄

This project is licensed under the MIT License.
