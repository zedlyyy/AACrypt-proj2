package com.proj2;

import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.proj2.cryptoUtility.AesCtrCrypto;
import com.proj2.cryptoUtility.OpeCrypto;
import com.proj2.cryptoUtility.PaillierCrypto;
import com.proj2.cryptoUtility.RsaMultiplicativeCrypto;

public class MainBootstrap {
    public static void main(String[] args) {
        String csvFilePath = "src/main/java/com/proj2/Company-Employee.Database/Dataset-Emp-Database.csv";
        String indexFilePath = "client_index.json";

        try {
            System.out.println("Starting Client Bootstrap...");

            // Generate keys
            SecretKey deterministicKey = AesCtrCrypto.generateKey();
            SecretKey randomKey = AesCtrCrypto.generateKey();
            PaillierCrypto.KeyPair paillierKeys = PaillierCrypto.generateKeyPair(2048);
            RsaMultiplicativeCrypto.RsaKeyPair rsaKeys = RsaMultiplicativeCrypto.generateKeyPair(2048);
            OpeCrypto ope = new OpeCrypto();

            // Connect to DB
            System.out.println("Connecting to DB...");
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/company_db", "root", "password");
            Statement statement = connection.createStatement();

            // Create table
            statement.execute("DROP TABLE IF EXISTS encrypted_employees");
            String createTableQuery = "CREATE TABLE IF NOT EXISTS encrypted_employees (id INT AUTO_INCREMENT PRIMARY KEY, employeeID_DET TEXT, fullName_RND TEXT, age_OPE BIGINT, departmentID_DET TEXT, salary_OPE BIGINT, salary_PAILLIER TEXT, salary_RSA TEXT, bonusEligibility_DET TEXT)";
            statement.execute(createTableQuery);
            System.out.println("DB structure successfully initialized!");
            
            // Fill table with .csv values
            System.out.println("Inserting dataset...");
            FileReader fileReader = new FileReader(csvFilePath);

            Iterable<CSVRecord> records = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build().parse(fileReader);
            String insertValuesQuery = "INSERT INTO encrypted_employees (employeeID_DET, fullName_RND, age_OPE, departmentID_DET, salary_OPE, salary_PAILLIER, salary_RSA, bonusEligibility_DET) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            
            PreparedStatement preparedStatement = connection.prepareStatement(insertValuesQuery);
            int rowCount = 0;

            for (CSVRecord record : records) {
                String empID = record.get("employeeID");
                String fullName = record.get("Full Name");
                int age = Integer.parseInt(record.get("Age"));
                String deptID = record.get("DepartmentID");
                int salary = Integer.parseInt(record.get("Salary"));
                String bonusEligibility = record.get("BonusEligibiity");

                String encEmpID = AesCtrCrypto.encryptDeterministic(empID, deterministicKey);
                String encFullName = AesCtrCrypto.encrypt(fullName, randomKey);
                long opeAge = ope.encrypt(age);
                String encDeptID = AesCtrCrypto.encryptDeterministic(deptID, deterministicKey);
                long opeSalary = ope.encrypt(salary);

                BigInteger paillierSalary = PaillierCrypto.encrypt(salary, paillierKeys.publicKey);
                BigInteger rsaSalary = RsaMultiplicativeCrypto.encrypt(salary, rsaKeys.publicKey);

                String encBonusEligibility = AesCtrCrypto.encryptDeterministic(bonusEligibility, deterministicKey);

                preparedStatement.setString(1, encEmpID);
                preparedStatement.setString(2, encFullName);
                preparedStatement.setLong(3, opeAge);
                preparedStatement.setString(4, encDeptID);
                preparedStatement.setLong(5, opeSalary);
                preparedStatement.setString(6, paillierSalary.toString());
                preparedStatement.setString(7, rsaSalary.toString());
                preparedStatement.setString(8, encBonusEligibility);

                preparedStatement.executeUpdate();
                rowCount++;
            }
            fileReader.close();
            System.out.println("Successfully encrypted values and inserted them into DB.");
            System.out.println("Rows inserted: " + rowCount);
            
            System.out.println("Saving client index...");
            ClientIndex index = new ClientIndex();
            index.deterministicKeyBase64 = Base64.getEncoder().encodeToString(deterministicKey.getEncoded());
            index.randomKeyBase64 = Base64.getEncoder().encodeToString(randomKey.getEncoded());
            index.paillierKeyPair = paillierKeys;
            index.rsaKeyPair = rsaKeys;
            index.ope = ope;

            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            try (FileWriter fileWriter = new FileWriter(indexFilePath)) {
                gson.toJson(index, fileWriter);
            }

            System.out.println("Client index saved!");
            preparedStatement.close();
            statement.close();
            connection.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
