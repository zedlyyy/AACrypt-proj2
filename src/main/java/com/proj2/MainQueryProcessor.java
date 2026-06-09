package com.proj2;

import java.io.FileReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.proj2.cryptoUtility.AesCtrCrypto;

public class MainQueryProcessor {

    private static ClientIndex clientIndex;
    private static SecretKey deterministicKey;
    private static SecretKey randomKey;
    private static Connection connection;

    public static void main(String[] args) {
        String indexFilePath = "client_index.json";

        try {
            System.out.println("Initializing Query Processor");

            Gson gson = new Gson();
            try (FileReader reader = new FileReader(indexFilePath)) {
                clientIndex = gson.fromJson(reader, ClientIndex.class);
            }

            byte[] detKeyBytes = Base64.getDecoder().decode(clientIndex.deterministicKeyBase64);
            deterministicKey = new SecretKeySpec(detKeyBytes, "AES");

            byte[] rndKeyBytes = Base64.getDecoder().decode(clientIndex.randomKeyBase64);
            randomKey = new SecretKeySpec(rndKeyBytes, "AES");

            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/company_db?allowPublicKeyRetrieval=true&useSSL=false", "root", "password");

            // exs
            runSearchByEmployeeID("EMP1005");

            runSearchByDepartment("DPT109");

            runFindHighestSalaryEmployee();

            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void runSearchByEmployeeID(String empID) throws Exception {
        System.out.println("Running a search on employee ID: " + empID);

        String encryptedQuery = AesCtrCrypto.encryptDeterministic(empID, deterministicKey);

        String sqlQuery = "SELECT * FROM encrypted_employees WHERE employeeID_DET = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, encryptedQuery);
            try (ResultSet res = preparedStatement.executeQuery()) {
                if (res.next()) {
                    String encName = res.getString("fullName_RND");
                    String plaintextName = AesCtrCrypto.decrypt(encName, randomKey);

                    long opeAge = res.getLong("age_OPE");
                    int plaintextAge = clientIndex.ope.decrypt(opeAge);

                    System.out.println("Full Name: " + plaintextName);
                    System.out.println("Age: " + plaintextAge);
                } else {
                    System.out.println("No matches were found");
                }
            }
        }
    }

    private static void runSearchByDepartment(String departmentID) throws Exception {
        System.out.println("Searching for employees in department ID: " + departmentID);

        String encryptedDepartment = AesCtrCrypto.encryptDeterministic(departmentID, deterministicKey);

        String sqlQuery = "SELECT * FROM encrypted_employees WHERE departmentID_DET = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, encryptedDepartment);
            try (ResultSet res = preparedStatement.executeQuery()) {
                int employeeCounter = 0;
                while (res.next()) {
                    String plaintextEmpID = AesCtrCrypto.decryptDeterministic(res.getString("employeeID_DET"), deterministicKey);
                    String plaintextName = AesCtrCrypto.decrypt(res.getString("fullName_RND"), randomKey);
                    employeeCounter++;

                    System.out.println("Match number " + employeeCounter);
                    System.out.println("Employee ID: " + plaintextEmpID);
                    System.out.println("Full Name: " + plaintextName);
                }
            }
        }
    }

    private static void runFindHighestSalaryEmployee() throws Exception {
        System.out.println("Searching for the highest salary employee...");

        String sqlQuery = "SELECT * FROM encrypted_employees ORDER BY salary_OPE DESC LIMIT 1";
        try (Statement statement = connection.createStatement()) {
            ResultSet res = statement.executeQuery(sqlQuery);
            if (res.next()) {
                String plaintextName = AesCtrCrypto.decrypt(res.getString("fullName_RND"), randomKey);
                long opeSalary = res.getLong("salary_OPE");
                int plaintextSalary = clientIndex.ope.decrypt(opeSalary);

                System.out.println("Highest paid employee:");
                System.out.println("Full Name: " + plaintextName);
                System.out.println("Salary: " + plaintextSalary);
            }
        }
    }
    
}
