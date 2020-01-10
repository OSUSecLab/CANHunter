package edu.osu.seclab.main;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

public class Common {
    public static final String BLE_API = "<android.bluetooth.BluetoothGatt: boolean writeCharacteristic(android.bluetooth.BluetoothGattCharacteristic)>";
    public static final String BLE_SETVALUE_BYTE = "<android.bluetooth.BluetoothGattCharacteristic: boolean setValue(byte[])>";
    public static final String BLE_SETVALUE_STR = "<android.bluetooth.BluetoothGattCharacteristic: boolean setValue(java.lang.String)>";
    public static final String CARLY = "<com.iViNi.communication.ConnectionThreadBT: void write(byte[])>";

    public static final String SOCKET_API_1 = "<java.io.OutputStream: void write(byte[])>";
    public static final String SOCKET_API_2 = "<java.io.OutputStream: void write(byte[],int,int)>";
    public static final String SOCKET_API_3 = "<java.io.OutputStream: void write(int)>";

    public static final String ECU_PAR_API = "<com.carly.lib_main_dataclasses_basic.ECUParameter: void <init>(int,java.lang.String,int,java.lang.String,java.lang.String,java.lang.String,int,int,int,int,int,int,float,float,java.lang.String,java.lang.String,java.lang.String,float,float,java.lang.String,int,java.lang.String,java.lang.String,int,float)>";
    public static final String CAN_ID_API = "<com.iViNi.DataClasses.CAN_ID: void <init>(java.lang.String,java.lang.String,int)>";

    public static final ArrayList<String> models = new ArrayList<>(List.of("Acura", "AlfaRomeo", "AstonMartin", "Audi", "Bentley", "BMW", "Bugatti", "Buick", "Cadillac", "Chevrolet",
            "Chrysler", "Citroen", "Dodge", "Ferrari", "Fiat", "Ford", "Geely", "GeneralMotors", "GMC", "Honda", "Hyundai",
            "Infiniti", "Jaguar", "Jeep", "Kia", "Koenigsegg", "Laborghini", "Rover", "Lexus", "Maserati", "Mazda", "Mclaren",
            "MB", "Mercedes", "Benz", "Mini", "Mitsubishi", "Nissan", "Pagani", "Peugeot", "Porsche", "Ram", "Renault",
            "RollsRoyce", "Saab", "Subaru", "Suzuki", "TataMotors", "Tesla", "Toyota", "Volkswagen", "Volvo", "Polo", "VAG", "VW",
            "Skoda", "Seat", "Beetle", "Scion", "Alpine", "GM", "Pontiac", "BYD", "Opel",
            "A3", "A4", "R8", "A1",  // Audi
            "i3", "i8", "X5", "Series3", "Series5",  // BMW
            "Tang", "Qin",  // BYD
            "Camaro", "Corvette", "Cruze", "Impala", "Malibu", "Suburban", "Volt",  // Chevrolet
            "Civic", "Fit", "Commodore", "Accord", "CR-V", "Elantra", "Accent", "Sonata",  // Honda
            "Camry", "Corolla", "Hilux", "Mirai", "Prius", "RAV4",  // Toyota
            "Gol", "Golf", "Passat", "Jetta",  // Volkswagen
            "Leaf", "Maxima", "Micra", "Qashqai", "RogueSport", "Tiida", "Versa", "Sunny", "Sentra", "Pulsar", "Almera",  // Nissan
            "Astra", "Corsa",  // Opel
            "Boxster", "Cayenne",  // Porsche
            "Clio", "Twingo", "Zoe",  // Renault
            "Ibiza")); // Seat

    public static String findModel(String s) {
        for (String model : models) {
            if (s.contains(model))
                return model;
        }
        return null;
    }

}
