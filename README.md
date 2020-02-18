# CANHunter

**CANHunter** is a tool for extracting CAN bus commands from car companion mobile apps. It has been implemented on both Android and iOS platforms. The dataset is also availble under the [Data](https://github.com/OSUSecLab/CANHunter/tree/master/Data) folder.

For more details about **CANHunter**, please refer to our paper [Automated Cross-Platform Reverse Engineering of CAN Bus Commands From Mobile Apps](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24231.pdf).


## Dependency
To run **CANHunter**, the following dependencies need to be satisfied:

- On your desktop / laptop
  - **IDA Pro**
  - **Frida**
  - **Cycript**
  - **Soot**
  
- On your smartphone (a jail-broken iPhone is required)
  - **Frida** (must exactly match Frida version on your desktop / laptop)
  - **Cycript**
